//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 -cc clang -cflags "-O2 -g -Wall" provenance bpf/provenance.bpf.c -- -Ibpf

package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"gopkg.in/yaml.v3"
)

const (
	rclcppLibraryPath = "/opt/ros/jazzy/lib/librclcpp.so"

	rclcppExecuteSubscriptionSymbol = "_ZN6rclcpp8Executor20execute_subscriptionESt10shared_ptrINS_16SubscriptionBaseEE"
	rclcppAddSubscriptionSymbol     = "_ZN6rclcpp15node_interfaces10NodeTopics16add_subscriptionESt10shared_ptrINS_16SubscriptionBaseEES2_INS_13CallbackGroupEE"
	rclcppGetTopicNameSymbol        = "_ZNK6rclcpp16SubscriptionBase14get_topic_nameEv"

	ddsLibraryPath = "/opt/ros/jazzy/lib/libfastrtps.so.2.14.6"

	newLocalWriterProxyDataSymbol = "_ZN8eprosima8fastrtps4rtps3EDP23newLocalWriterProxyDataEPNS1_10RTPSWriterERKNS0_15TopicAttributesERKNS_7fastdds3dds9WriterQosE"
	statefulUnsentSymbol          = "_ZN8eprosima8fastrtps4rtps14StatefulWriter30unsent_change_added_to_historyEPNS1_13CacheChange_tERKNSt6chrono10time_pointINS5_3_V212steady_clockENS5_8durationIlSt5ratioILl1ELl1000000000EEEEEE"

	supportedVersion    = 1
	selectorTopicMaxLen = 64
	topicNameMaxLen     = 64

	bpffsPinDir             = "/sys/fs/bpf/ros2_security"
	sampleProvenancePinPath = bpffsPinDir + "/sample_provenance"
)

type runtimeManifest struct {
	Version           int              `yaml:"version"`
	Artifact          string           `yaml:"artifact"`
	ManifestID        string           `yaml:"manifest_id"`
	CallbackInstances []callbackConfig `yaml:"callback_instances"`
	Topics            []topicConfig    `yaml:"topics"`
}

type callbackConfig struct {
	CallbackInstanceID uint32         `yaml:"callback_instance_id"`
	Selector           selectorConfig `yaml:"selector"`
	CallbackHint       string         `yaml:"callback_hint,omitempty"`
}

type topicConfig struct {
	TopicID uint32 `yaml:"topic_id"`
	ROSName string `yaml:"ros_name"`
	DDSName string `yaml:"dds_name"`
}

type selectorConfig struct {
	InputTopic string `yaml:"input_topic"`
	Instance   uint32 `yaml:"instance"`
}

type resolvedSubscription struct {
	CallbackInstanceID uint32
	InputTopic         string
	Instance           uint32
	CallbackHint       string
}

type subscriptionSelectorKey struct {
	Topic    [selectorTopicMaxLen]byte
	Instance uint32
}

type subscriptionSelectorValue struct {
	CallbackInstanceID uint32
}

type topicRegistryKey struct {
	Topic [topicNameMaxLen]byte
}

type topicRegistryValue struct {
	TopicID uint32
}

func normalizeROSTopicName(topic string) string {
	topic = strings.TrimSpace(topic)
	if topic == "" {
		return ""
	}
	if !strings.HasPrefix(topic, "/") {
		topic = "/" + topic
	}
	return topic
}

func loadRuntimeManifest(path string) (*runtimeManifest, [32]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("read runtime manifest %q: %w", path, err)
	}

	var config runtimeManifest

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	if err := decoder.Decode(&config); err != nil {
		return nil, [32]byte{}, fmt.Errorf("parse runtime manifest %q: %w", path, err)
	}

	if err := validateRuntimeManifest(&config); err != nil {
		return nil, [32]byte{}, fmt.Errorf("invalid runtime manifest %q: %w", path, err)
	}

	return &config, sha256.Sum256(data), nil
}

/*
validateRuntimeManifest validates only runtime identities. It does not load or
interpret the enforcement allowlist.
*/
func validateRuntimeManifest(config *runtimeManifest) error {
	if config.Version != supportedVersion {
		return fmt.Errorf(
			"unsupported policy version %d; expected %d",
			config.Version,
			supportedVersion,
		)
	}

	config.Artifact = strings.TrimSpace(config.Artifact)
	if config.Artifact != "runtime_manifest" {
		return fmt.Errorf(
			"artifact must be runtime_manifest, got %q",
			config.Artifact,
		)
	}
	config.ManifestID = strings.TrimSpace(config.ManifestID)
	if config.ManifestID == "" {
		return errors.New("manifest_id is required")
	}

	if len(config.CallbackInstances) == 0 {
		return errors.New("at least one callback selector is required")
	}
	if len(config.Topics) == 0 {
		return errors.New("at least one output topic identity is required")
	}

	seenSelectors := make(map[string]struct{})
	seenCallbackIDs := make(map[uint32]struct{})

	for i := range config.CallbackInstances {
		cb := &config.CallbackInstances[i]
		if cb.CallbackInstanceID == 0 {
			return fmt.Errorf("callback_instances[%d].callback_instance_id must be non-zero", i)
		}
		if _, exists := seenCallbackIDs[cb.CallbackInstanceID]; exists {
			return fmt.Errorf("duplicate callback_instance_id %d", cb.CallbackInstanceID)
		}
		seenCallbackIDs[cb.CallbackInstanceID] = struct{}{}

		cb.Selector.InputTopic =
			normalizeROSTopicName(cb.Selector.InputTopic)

		cb.CallbackHint =
			strings.TrimSpace(cb.CallbackHint)

		if cb.Selector.InputTopic == "" {
			return fmt.Errorf(
				"callback_instances[%d].selector.input_topic is required",
				i,
			)
		}

		if len(cb.Selector.InputTopic)+1 > selectorTopicMaxLen {
			return fmt.Errorf(
				"input topic %q exceeds %d bytes including NUL",
				cb.Selector.InputTopic,
				selectorTopicMaxLen,
			)
		}

		/*
			Current runtime selector implementation has been verified for
			instance=1. Multi-instance disambiguation is a later extension.
		*/
		if cb.Selector.Instance != 1 {
			return fmt.Errorf(
				"selector (%s, instance=%d) is unsupported in the current verified prototype",
				cb.Selector.InputTopic,
				cb.Selector.Instance,
			)
		}

		selectorID :=
			fmt.Sprintf(
				"%s#%d",
				cb.Selector.InputTopic,
				cb.Selector.Instance,
			)

		if _, exists := seenSelectors[selectorID]; exists {
			return fmt.Errorf(
				"duplicate callback selector %s",
				selectorID,
			)
		}

		seenSelectors[selectorID] = struct{}{}
	}

	seenTopicIDs := make(map[uint32]struct{})
	seenDDSNames := make(map[string]struct{})
	for i := range config.Topics {
		topic := &config.Topics[i]
		topic.ROSName = normalizeROSTopicName(topic.ROSName)
		topic.DDSName = strings.TrimSpace(topic.DDSName)
		if topic.TopicID == 0 {
			return fmt.Errorf("topics[%d].topic_id must be non-zero", i)
		}
		if topic.ROSName == "" || topic.DDSName == "" {
			return fmt.Errorf("topics[%d] requires ros_name and dds_name", i)
		}
		if len(topic.DDSName)+1 > topicNameMaxLen {
			return fmt.Errorf("DDS topic %q exceeds %d bytes including NUL", topic.DDSName, topicNameMaxLen)
		}
		if _, exists := seenTopicIDs[topic.TopicID]; exists {
			return fmt.Errorf("duplicate topic_id %d", topic.TopicID)
		}
		if _, exists := seenDDSNames[topic.DDSName]; exists {
			return fmt.Errorf("duplicate DDS topic name %q", topic.DDSName)
		}
		seenTopicIDs[topic.TopicID] = struct{}{}
		seenDDSNames[topic.DDSName] = struct{}{}
	}

	return nil
}

/*
CallbackInstanceIDs are assigned explicitly by the policy generator's
compilation stage and carried unchanged in the runtime manifest.
*/
func resolveSubscriptions(
	config *runtimeManifest,
) ([]resolvedSubscription, error) {
	resolved :=
		make(
			[]resolvedSubscription,
			0,
			len(config.CallbackInstances),
		)

	for _, cb := range config.CallbackInstances {
		resolved = append(
			resolved,
			resolvedSubscription{
				CallbackInstanceID: cb.CallbackInstanceID,
				InputTopic:         cb.Selector.InputTopic,
				Instance:           cb.Selector.Instance,
				CallbackHint:       cb.CallbackHint,
			},
		)
	}

	return resolved, nil
}

func makeSubscriptionSelectorKey(
	topic string,
	instance uint32,
) (subscriptionSelectorKey, error) {
	var key subscriptionSelectorKey

	topic = normalizeROSTopicName(topic)

	if topic == "" {
		return key, errors.New("empty selector topic")
	}

	if len(topic)+1 > len(key.Topic) {
		return key, fmt.Errorf(
			"selector topic %q exceeds %d bytes including NUL",
			topic,
			len(key.Topic),
		)
	}

	copy(key.Topic[:], []byte(topic))
	key.Instance = instance

	return key, nil
}

/*
Populate only the runtime selector -> CallbackInstanceID map.

There is deliberately no callback/output ALLOW/DENY map in this module.
*/
func initializeSubscriptionSelectors(
	objs *provenanceObjects,
	subscriptions []resolvedSubscription,
) error {
	for _, sub := range subscriptions {
		key, err :=
			makeSubscriptionSelectorKey(
				sub.InputTopic,
				sub.Instance,
			)

		if err != nil {
			return err
		}

		value :=
			subscriptionSelectorValue{
				CallbackInstanceID: sub.CallbackInstanceID,
			}

		if err := objs.SubscriptionSelectorConfig.Put(
			key,
			value,
		); err != nil {
			return fmt.Errorf(
				"insert selector topic=%q instance=%d callback_instance_id=%d: %w",
				sub.InputTopic,
				sub.Instance,
				sub.CallbackInstanceID,
				err,
			)
		}
	}

	return nil
}

func makeTopicRegistryKey(topic string) (topicRegistryKey, error) {
	var key topicRegistryKey
	topic = strings.TrimSpace(topic)
	if topic == "" {
		return key, errors.New("empty DDS topic name")
	}
	if len(topic)+1 > len(key.Topic) {
		return key, fmt.Errorf("DDS topic %q exceeds %d bytes including NUL", topic, len(key.Topic))
	}
	copy(key.Topic[:], []byte(topic))
	return key, nil
}

func initializeTopicRegistry(objs *provenanceObjects, topics []topicConfig) error {
	for _, topic := range topics {
		key, err := makeTopicRegistryKey(topic.DDSName)
		if err != nil {
			return err
		}
		value := topicRegistryValue{TopicID: topic.TopicID}
		if err := objs.TopicRegistryConfig.Put(key, value); err != nil {
			return fmt.Errorf("insert DDS topic=%q topic_id=%d: %w", topic.DDSName, topic.TopicID, err)
		}
	}
	return nil
}

func removeIfExists(path string) error {
	err := os.Remove(path)

	if err == nil ||
		errors.Is(err, os.ErrNotExist) {
		return nil
	}

	return err
}

func pinMapFresh(
	m *ebpf.Map,
	path string,
) error {
	if err := removeIfExists(path); err != nil {
		return fmt.Errorf(
			"remove stale pin %q: %w",
			path,
			err,
		)
	}

	if err := m.Pin(path); err != nil {
		return fmt.Errorf(
			"pin map at %q: %w",
			path,
			err,
		)
	}

	return nil
}

/*
Only the provenance map crosses the process boundary.

The selector map stays private to the provenance tracker because the Mediator
does not need SubscriptionBase* runtime binding state.
*/
func pinSampleProvenance(
	objs *provenanceObjects,
) error {
	if err := os.MkdirAll(
		bpffsPinDir,
		0755,
	); err != nil {
		return fmt.Errorf(
			"create bpffs pin dir %q: %w",
			bpffsPinDir,
			err,
		)
	}

	return pinMapFresh(
		objs.SampleProv,
		sampleProvenancePinPath,
	)
}

func validateTargetBinary(
	path string,
) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf(
			"absolute target path: %w",
			err,
		)
	}

	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf(
			"access target binary %q: %w",
			abs,
			err,
		)
	}

	if info.IsDir() {
		return "", fmt.Errorf(
			"target path %q is a directory",
			abs,
		)
	}

	return abs, nil
}

func main() {
	if len(os.Args) != 3 {
		log.Fatalf(
			"usage: %s <runtime-manifest.yaml> <target-binary>",
			os.Args[0],
		)
	}

	manifestPath := os.Args[1]

	targetPath, err :=
		validateTargetBinary(os.Args[2])

	if err != nil {
		log.Fatalf(
			"target binary: %v",
			err,
		)
	}

	config, manifestHash, err :=
		loadRuntimeManifest(manifestPath)

	if err != nil {
		log.Fatalf(
			"load runtime identity manifest: %v",
			err,
		)
	}

	subscriptions, err :=
		resolveSubscriptions(config)

	if err != nil {
		log.Fatalf(
			"resolve CallbackInstanceIDs: %v",
			err,
		)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf(
			"remove memlock limit: %v",
			err,
		)
	}

	var objs provenanceObjects

	if err := loadProvenanceObjects(
		&objs,
		nil,
	); err != nil {
		log.Fatalf(
			"load provenance eBPF objects: %v",
			err,
		)
	}
	defer objs.Close()

	if err := initializeSubscriptionSelectors(
		&objs,
		subscriptions,
	); err != nil {
		log.Fatalf(
			"initialize callback selectors: %v",
			err,
		)
	}

	if err := initializeTopicRegistry(&objs, config.Topics); err != nil {
		log.Fatalf("initialize output topic registry: %v", err)
	}

	if err := pinSampleProvenance(
		&objs,
	); err != nil {
		log.Fatalf(
			"pin sample provenance: %v",
			err,
		)
	}

	defer func() {
		if err := removeIfExists(
			sampleProvenancePinPath,
		); err != nil {
			log.Printf(
				"warning: remove pinned provenance map: %v",
				err,
			)
		}
	}()

	/*
		Attach to target main() first.

		Start this loader before launching the target ROS 2 process so the
		target TGID is captured at process entry.
	*/
	rosExecutable, err :=
		link.OpenExecutable(targetPath)

	if err != nil {
		log.Fatalf(
			"open target binary %q: %v",
			targetPath,
			err,
		)
	}

	targetStartLink, err :=
		rosExecutable.Uprobe(
			"main",
			objs.TraceTargetStart,
			nil,
		)

	if err != nil {
		log.Fatalf(
			"attach target main uprobe: %v",
			err,
		)
	}
	defer targetStartLink.Close()

	rclcppExecutable, err :=
		link.OpenExecutable(
			rclcppLibraryPath,
		)

	if err != nil {
		log.Fatalf(
			"open rclcpp library %q: %v",
			rclcppLibraryPath,
			err,
		)
	}

	addSubscriptionLink, err :=
		rclcppExecutable.Uprobe(
			rclcppAddSubscriptionSymbol,
			objs.TraceRclcppAddSubscription,
			nil,
		)

	if err != nil {
		log.Fatalf(
			"attach NodeTopics::add_subscription: %v",
			err,
		)
	}
	defer addSubscriptionLink.Close()

	executeSubscriptionEnterLink, err :=
		rclcppExecutable.Uprobe(
			rclcppExecuteSubscriptionSymbol,
			objs.TraceRclcppExecuteSubscriptionEnter,
			nil,
		)

	if err != nil {
		log.Fatalf(
			"attach Executor::execute_subscription entry: %v",
			err,
		)
	}
	defer executeSubscriptionEnterLink.Close()

	executeSubscriptionExitLink, err :=
		rclcppExecutable.Uretprobe(
			rclcppExecuteSubscriptionSymbol,
			objs.TraceRclcppExecuteSubscriptionExit,
			nil,
		)

	if err != nil {
		log.Fatalf(
			"attach Executor::execute_subscription return: %v",
			err,
		)
	}
	defer executeSubscriptionExitLink.Close()

	getTopicNameEnterLink, err :=
		rclcppExecutable.Uprobe(
			rclcppGetTopicNameSymbol,
			objs.TraceRclcppGetTopicNameEnter,
			nil,
		)

	if err != nil {
		log.Fatalf(
			"attach SubscriptionBase::get_topic_name entry: %v",
			err,
		)
	}
	defer getTopicNameEnterLink.Close()

	getTopicNameExitLink, err :=
		rclcppExecutable.Uretprobe(
			rclcppGetTopicNameSymbol,
			objs.TraceRclcppGetTopicNameExit,
			nil,
		)

	if err != nil {
		log.Fatalf(
			"attach SubscriptionBase::get_topic_name return: %v",
			err,
		)
	}
	defer getTopicNameExitLink.Close()

	ddsExecutable, err :=
		link.OpenExecutable(
			ddsLibraryPath,
		)

	if err != nil {
		log.Fatalf(
			"open Fast DDS library %q: %v",
			ddsLibraryPath,
			err,
		)
	}

	writerDiscoveryLink, err :=
		ddsExecutable.Uprobe(
			newLocalWriterProxyDataSymbol,
			objs.TraceNewLocalWriterProxyData,
			nil,
		)

	if err != nil {
		log.Fatalf(
			"attach EDP::newLocalWriterProxyData: %v",
			err,
		)
	}
	defer writerDiscoveryLink.Close()

	statefulUnsentLink, err :=
		ddsExecutable.Uprobe(
			statefulUnsentSymbol,
			objs.TraceStatefulUnsent,
			nil,
		)

	if err != nil {
		log.Fatalf(
			"attach StatefulWriter::unsent_change_added_to_history: %v",
			err,
		)
	}
	defer statefulUnsentLink.Close()

	fmt.Println("========================================")
	fmt.Println("ROS 2 Trusted Runtime Provenance Tracker")
	fmt.Println("========================================")
	fmt.Printf(
		"runtime_manifest_source=%s\n",
		manifestPath,
	)
	fmt.Printf(
		"runtime_manifest_sha256=%x\n",
		manifestHash,
	)
	fmt.Printf("runtime_manifest_id=%s\n", config.ManifestID)
	fmt.Printf(
		"target_binary=%s\n",
		targetPath,
	)
	fmt.Printf(
		"sample_provenance_pin=%s\n",
		sampleProvenancePinPath,
	)
	fmt.Println("authorization=NONE")
	fmt.Println("kernel_bypass_guard=SEPARATE_MODULE")
	fmt.Println()

	for _, sub := range subscriptions {
		fmt.Printf(
			"[CALLBACK_SELECTOR] id=%d selector=(%s,%d) hint=%s\n",
			sub.CallbackInstanceID,
			sub.InputTopic,
			sub.Instance,
			sub.CallbackHint,
		)
	}
	for _, topic := range config.Topics {
		fmt.Printf("[TOPIC_REGISTRY] id=%d ros=%s dds=%s\n", topic.TopicID, topic.ROSName, topic.DDSName)
	}

	fmt.Println()
	fmt.Println("Tracked provenance:")
	fmt.Println("  SubscriptionBase* -> CallbackInstanceID")
	fmt.Println("  RTPSWriter* -> TopicID")
	fmt.Println("  (Writer GUID, Sequence Number) -> {CallbackInstanceID, TopicID}")
	fmt.Println()
	fmt.Println("This process does NOT perform ALLOW/DENY decisions.")
	fmt.Println("Start this tracker BEFORE the target ROS 2 process.")
	fmt.Println("Press Ctrl+C to stop.")

	stop := make(chan os.Signal, 1)

	signal.Notify(
		stop,
		os.Interrupt,
		syscall.SIGTERM,
	)

	sig := <-stop

	fmt.Printf(
		"Received signal: %v\n",
		sig,
	)

	fmt.Println(
		"Detaching provenance probes and removing pinned provenance map path...",
	)
}
