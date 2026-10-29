#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define TOPIC_UNKNOWN 0

#define TOPIC_NAME_OFFSET  16
#define TOPIC_NAME_MAX_LEN 64

/*
 * CacheChange_t layout verified on the actual experiment host:
 *   ROS 2 Jazzy / Fast DDS 2.14.6 / ARM64
 *
 *   sizeof(CacheChange_t)         = 240
 *   writerGUID offset             = 12
 *   SequenceNumber_t offset       = 48
 *   SequenceNumber_t.high offset  = 0
 *   SequenceNumber_t.low offset   = 4
 */
#define CACHECHANGE_WRITER_GUID_OFFSET 12
#define CACHECHANGE_SEQUENCE_OFFSET    48

struct thread_key
{
    __u32 tgid;
    __u32 tid;
};

struct writer_key
{
    __u32 tgid;
    __u32 pad;
    __u64 writer_ptr;
};

struct subscription_key
{
    __u32 tgid;
    __u32 pad;
    __u64 subscription_ptr;
};

struct callback_instance_context
{
    __u32 callback_instance_id;
};

struct writer_topic_context
{
    __u32 topic_id;
    __u32 reserved;
};

/*
 * Cross-process provenance key.
 *
 * The Trusted Mediator reconstructs the same key from the received
 * CacheChange_t:
 *
 *   (Writer GUID, Sequence Number)
 */
struct sample_identity_key
{
    __u8 writer_guid[16];
    __s32 seq_high;
    __u32 seq_low;
};

struct sample_provenance_value
{
    __u32 callback_instance_id;
    __u32 topic_id;
};

struct target_state
{
    __u32 tgid;
};

struct registered_subscription_context
{
    __u32 registered;
};

struct active_subscription_context
{
    __u64 subscription_ptr;
};

struct subscription_instance_context
{
    __u32 callback_instance_id;
};

struct get_topic_context
{
    __u64 subscription_ptr;
};

/*
 * Stable selector used by the current prototype:
 *
 *   (input topic, instance) -> CallbackInstanceID
 *
 * The userspace provenance loader populates this map from the compiled
 * runtime identity manifest. This map is used only for runtime binding;
 * it does NOT contain output authorization decisions.
 */
struct subscription_selector_key
{
    char topic[TOPIC_NAME_MAX_LEN];
    __u32 instance;
};

struct subscription_selector_value
{
    __u32 callback_instance_id;
};

struct topic_registry_key
{
    char topic[TOPIC_NAME_MAX_LEN];
};

struct topic_registry_value
{
    __u32 topic_id;
};

/*
 * key=0 only.
 * Used to scope global librclcpp/libfastrtps uprobes to the target process.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct target_state);
} target_state_map SEC(".maps");

/*
 * (TGID, SubscriptionBase*) -> registered
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct subscription_key);
    __type(value, struct registered_subscription_context);
} registered_subscription_by_key SEC(".maps");

/*
 * (TGID, TID) -> currently executing SubscriptionBase*
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct thread_key);
    __type(value, struct active_subscription_context);
} active_subscription_by_thread SEC(".maps");

/*
 * Runtime identity:
 *
 * (TGID, SubscriptionBase*) -> CallbackInstanceID
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct subscription_key);
    __type(value, struct subscription_instance_context);
} subscription_instance_by_key SEC(".maps");

/*
 * Runtime binding configuration:
 *
 * (input topic, instance) -> CallbackInstanceID
 *
 * This is NOT an ALLOW/DENY policy map.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct subscription_selector_key);
    __type(value, struct subscription_selector_value);
} subscription_selector_config SEC(".maps");

/*
 * Runtime output identity registry populated from runtime_manifest.yaml:
 *
 *   DDS topic name -> TopicID
 *
 * This map contains identity configuration only, never authorization state.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct topic_registry_key);
    __type(value, struct topic_registry_value);
} topic_registry_config SEC(".maps");

/*
 * get_topic_name() entry/return temporary state.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct thread_key);
    __type(value, struct get_topic_context);
} get_topic_by_thread SEC(".maps");

/*
 * (TGID, TID) -> active CallbackInstanceID
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct thread_key);
    __type(value, struct callback_instance_context);
} active_callback_instance_by_thread SEC(".maps");

/*
 * (TGID, RTPSWriter*) -> output TopicID
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct writer_key);
    __type(value, struct writer_topic_context);
} writer_topic_by_key SEC(".maps");

/*
 * Cross-process sample provenance.
 *
 * key:
 *   (Writer GUID, Sequence Number)
 *
 * value:
 *   (CallbackInstanceID, output TopicID)
 *
 * The userspace provenance loader pins this map in bpffs so the Trusted
 * Mediator can look it up. This map contains provenance only; it does not
 * contain authorization state.
 */
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct sample_identity_key);
    __type(value, struct sample_provenance_value);
} sample_prov SEC(".maps");

static __always_inline struct thread_key current_thread_key(void)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct thread_key key = {
        .tgid = (__u32)(pid_tgid >> 32),
        .tid = (__u32)pid_tgid,
    };

    return key;
}

static __always_inline struct writer_key make_writer_key(
    __u32 tgid,
    __u64 writer_ptr)
{
    struct writer_key key = {
        .tgid = tgid,
        .pad = 0,
        .writer_ptr = writer_ptr,
    };

    return key;
}

static __always_inline struct subscription_key make_subscription_key(
    __u32 tgid,
    __u64 subscription_ptr)
{
    struct subscription_key key = {
        .tgid = tgid,
        .pad = 0,
        .subscription_ptr = subscription_ptr,
    };

    return key;
}

static __always_inline int is_target_tgid(__u32 tgid)
{
    __u32 zero = 0;

    struct target_state *state =
        bpf_map_lookup_elem(
            &target_state_map,
            &zero
        );

    if (!state)
    {
        return 0;
    }

    return state->tgid == tgid;
}

static __always_inline int set_callback_instance_context(
    struct thread_key *key,
    __u32 callback_instance_id)
{
    struct callback_instance_context active_instance_ctx = {
        .callback_instance_id = callback_instance_id,
    };

    int err = bpf_map_update_elem(
        &active_callback_instance_by_thread,
        key,
        &active_instance_ctx,
        BPF_ANY
    );

    if (err != 0)
    {
        bpf_printk(
            "PROV_ACTIVE_SET_FAIL tgid=%u tid=%u err=%d",
            key->tgid,
            key->tid,
            err
        );
        return err;
    }

    bpf_printk(
        "PROV_ACTIVE_SET tgid=%u tid=%u cb=%u",
        key->tgid,
        key->tid,
        callback_instance_id
    );

    return 0;
}

static __always_inline void clear_execution_context(
    struct thread_key *key)
{
    bpf_map_delete_elem(
        &active_callback_instance_by_thread,
        key
    );

    bpf_map_delete_elem(
        &active_subscription_by_thread,
        key
    );
}

/*
 * Target executable main() entry.
 *
 * No policy decision is made here. We only capture the target TGID so
 * library-wide uprobes ignore other processes.
 */
SEC("uprobe/target_start")
int trace_target_start(struct pt_regs *ctx)
{
    struct thread_key key = current_thread_key();
    __u32 zero = 0;

    struct target_state state = {
        .tgid = key.tgid,
    };

    int err = bpf_map_update_elem(
        &target_state_map,
        &zero,
        &state,
        BPF_ANY
    );

    if (err == 0)
    {
        bpf_printk(
            "PROV_TARGET_SET tgid=%u",
            key.tgid
        );
    }

    return 0;
}

/*
 * rclcpp::node_interfaces::NodeTopics::add_subscription(
 *     std::shared_ptr<SubscriptionBase>,
 *     std::shared_ptr<CallbackGroup>
 * )
 *
 * Verified on the experiment host (ARM64):
 *   x1 = shared_ptr argument storage
 *   [x1] = SubscriptionBase*
 */
SEC("uprobe/rclcpp_add_subscription")
int trace_rclcpp_add_subscription(struct pt_regs *ctx)
{
    struct thread_key thread = current_thread_key();

    if (!is_target_tgid(thread.tgid))
    {
        return 0;
    }

    __u64 subscription_arg =
        (__u64)PT_REGS_PARM2(ctx);

    __u64 subscription_ptr = 0;

    if (subscription_arg == 0)
    {
        return 0;
    }

    long read_err = bpf_probe_read_user(
        &subscription_ptr,
        sizeof(subscription_ptr),
        (const void *)subscription_arg
    );

    if (read_err != 0 || subscription_ptr == 0)
    {
        return 0;
    }

    struct subscription_key sub_key =
        make_subscription_key(
            thread.tgid,
            subscription_ptr
        );

    struct registered_subscription_context registered = {
        .registered = 1,
    };

    int err = bpf_map_update_elem(
        &registered_subscription_by_key,
        &sub_key,
        &registered,
        BPF_ANY
    );

    if (err == 0)
    {
        bpf_printk(
            "PROV_SUB_REGISTER tgid=%u sub=%lx",
            thread.tgid,
            subscription_ptr
        );
    }

    return 0;
}

/*
 * rclcpp::Executor::execute_subscription(
 *     std::shared_ptr<SubscriptionBase>
 * ) entry
 *
 * Verified on the experiment host (ARM64):
 *   x0 = shared_ptr argument storage
 *   [x0] = SubscriptionBase*
 */
SEC("uprobe/rclcpp_execute_subscription_enter")
int trace_rclcpp_execute_subscription_enter(
    struct pt_regs *ctx)
{
    struct thread_key thread = current_thread_key();

    if (!is_target_tgid(thread.tgid))
    {
        return 0;
    }

    __u64 arg_storage =
        (__u64)PT_REGS_PARM1(ctx);

    __u64 subscription_ptr = 0;

    if (arg_storage == 0)
    {
        return 0;
    }

    long read_err = bpf_probe_read_user(
        &subscription_ptr,
        sizeof(subscription_ptr),
        (const void *)arg_storage
    );

    if (read_err != 0 || subscription_ptr == 0)
    {
        return 0;
    }

    /* Prevent stale context from leaking into the next callback execution. */
    bpf_map_delete_elem(
        &active_callback_instance_by_thread,
        &thread
    );

    struct active_subscription_context active = {
        .subscription_ptr = subscription_ptr,
    };

    int err = bpf_map_update_elem(
        &active_subscription_by_thread,
        &thread,
        &active,
        BPF_ANY
    );

    if (err != 0)
    {
        return 0;
    }

    bpf_printk(
        "PROV_EXEC_SUB tgid=%u tid=%u sub=%lx",
        thread.tgid,
        thread.tid,
        subscription_ptr
    );

    /*
     * If this SubscriptionBase* was already bound on a previous execution,
     * activate the CallbackInstanceID immediately.
     */
    struct subscription_key sub_key =
        make_subscription_key(
            thread.tgid,
            subscription_ptr
        );

    struct subscription_instance_context *instance_ctx =
        bpf_map_lookup_elem(
            &subscription_instance_by_key,
            &sub_key
        );

    if (instance_ctx)
    {
        set_callback_instance_context(
            &thread,
            instance_ctx->callback_instance_id
        );
    }

    return 0;
}

/*
 * execute_subscription() return = end of callback execution scope.
 */
SEC("uretprobe/rclcpp_execute_subscription_exit")
int trace_rclcpp_execute_subscription_exit(
    struct pt_regs *ctx)
{
    struct thread_key thread = current_thread_key();

    if (!is_target_tgid(thread.tgid))
    {
        return 0;
    }

    clear_execution_context(
        &thread
    );

    bpf_printk(
        "PROV_ACTIVE_DEL tgid=%u tid=%u",
        thread.tgid,
        thread.tid
    );

    return 0;
}

/*
 * rclcpp::SubscriptionBase::get_topic_name() const entry.
 *
 * Verified:
 *   x0 = SubscriptionBase* this
 */
SEC("uprobe/rclcpp_get_topic_name_enter")
int trace_rclcpp_get_topic_name_enter(
    struct pt_regs *ctx)
{
    struct thread_key thread = current_thread_key();

    if (!is_target_tgid(thread.tgid))
    {
        return 0;
    }

    __u64 subscription_ptr =
        (__u64)PT_REGS_PARM1(ctx);

    if (subscription_ptr == 0)
    {
        return 0;
    }

    struct get_topic_context topic_ctx = {
        .subscription_ptr = subscription_ptr,
    };

    bpf_map_update_elem(
        &get_topic_by_thread,
        &thread,
        &topic_ctx,
        BPF_ANY
    );

    return 0;
}

/*
 * get_topic_name() return.
 *
 * Verified:
 *   return x0 -> topic string
 *
 * This binds the runtime SubscriptionBase* to the deterministic
 * CallbackInstanceID assigned explicitly in the runtime identity manifest.
 *
 * No output authorization is evaluated here.
 */
SEC("uretprobe/rclcpp_get_topic_name_exit")
int trace_rclcpp_get_topic_name_exit(
    struct pt_regs *ctx)
{
    struct thread_key thread = current_thread_key();

    if (!is_target_tgid(thread.tgid))
    {
        return 0;
    }

    struct get_topic_context *topic_ctx =
        bpf_map_lookup_elem(
            &get_topic_by_thread,
            &thread
        );

    if (!topic_ctx)
    {
        return 0;
    }

    __u64 subscription_ptr =
        topic_ctx->subscription_ptr;

    __u64 topic_name_ptr =
        (__u64)PT_REGS_RC(ctx);

    struct subscription_selector_key selector = {};
    selector.instance = 1;

    if (topic_name_ptr == 0)
    {
        bpf_map_delete_elem(
            &get_topic_by_thread,
            &thread
        );
        return 0;
    }

    long read_len = bpf_probe_read_user_str(
        selector.topic,
        sizeof(selector.topic),
        (const void *)topic_name_ptr
    );

    if (read_len < 0)
    {
        bpf_map_delete_elem(
            &get_topic_by_thread,
            &thread
        );
        return 0;
    }

    struct subscription_key sub_key =
        make_subscription_key(
            thread.tgid,
            subscription_ptr
        );

    struct registered_subscription_context *registered =
        bpf_map_lookup_elem(
            &registered_subscription_by_key,
            &sub_key
        );

    if (!registered)
    {
        bpf_printk(
            "PROV_INSTANCE_UNREGISTERED sub=%lx topic=%s",
            subscription_ptr,
            selector.topic
        );

        bpf_map_delete_elem(
            &get_topic_by_thread,
            &thread
        );
        return 0;
    }

    struct subscription_selector_value *selector_value =
        bpf_map_lookup_elem(
            &subscription_selector_config,
            &selector
        );

    if (!selector_value)
    {
        bpf_printk(
            "PROV_SELECTOR_MISS sub=%lx topic=%s",
            subscription_ptr,
            selector.topic
        );

        bpf_map_delete_elem(
            &get_topic_by_thread,
            &thread
        );
        return 0;
    }

    struct subscription_instance_context instance_ctx = {
        .callback_instance_id = selector_value->callback_instance_id,
    };

    int bind_err = bpf_map_update_elem(
        &subscription_instance_by_key,
        &sub_key,
        &instance_ctx,
        BPF_ANY
    );

    if (bind_err == 0)
    {
        bpf_printk(
            "PROV_INSTANCE_BIND sub=%lx cb=%u topic=%s",
            subscription_ptr,
            instance_ctx.callback_instance_id,
            selector.topic
        );
    }

    /*
     * If get_topic_name() was called inside the current
     * execute_subscription() scope, activate the ID before the user callback
     * proceeds to publish.
     */
    struct active_subscription_context *active =
        bpf_map_lookup_elem(
            &active_subscription_by_thread,
            &thread
        );

    if (active &&
        active->subscription_ptr == subscription_ptr)
    {
        set_callback_instance_context(
            &thread,
            instance_ctx.callback_instance_id
        );
    }

    bpf_map_delete_elem(
        &get_topic_by_thread,
        &thread
    );

    return 0;
}

/*
 * eProsima Fast DDS:
 *
 * EDP::newLocalWriterProxyData(
 *     RTPSWriter* writer,
 *     TopicAttributes const& topic_attributes,
 *     WriterQos const& qos
 * )
 *
 * ARM64 member-function ABI:
 *   x0 = EDP* this
 *   x1 = RTPSWriter*
 *   x2 = TopicAttributes*
 *   x3 = WriterQos*
 */
SEC("uprobe/new_local_writer_proxy_data")
int trace_new_local_writer_proxy_data(
    struct pt_regs *ctx)
{
    struct thread_key thread =
        current_thread_key();

    if (!is_target_tgid(thread.tgid))
    {
        return 0;
    }

    __u64 writer_ptr =
        (__u64)PT_REGS_PARM2(ctx);

    __u64 topic_attributes_ptr =
        (__u64)PT_REGS_PARM3(ctx);

    char topic_name[TOPIC_NAME_MAX_LEN] = {};

    if (writer_ptr == 0 || topic_attributes_ptr == 0)
    {
        return 0;
    }

    const void *topic_name_ptr =
        (const void *)(
            topic_attributes_ptr +
            TOPIC_NAME_OFFSET
        );

    long read_len =
        bpf_probe_read_user_str(
            topic_name,
            sizeof(topic_name),
            topic_name_ptr
        );

    if (read_len < 0)
    {
        bpf_printk(
            "PROV_WRITER_TOPIC_READ_FAIL tgid=%u err=%ld",
            thread.tgid,
            read_len
        );
        return 0;
    }

    struct topic_registry_key registry_key = {};
    __builtin_memcpy(
        registry_key.topic,
        topic_name,
        sizeof(registry_key.topic)
    );

    struct topic_registry_value *registry_value =
        bpf_map_lookup_elem(
            &topic_registry_config,
            &registry_key
        );

    /*
     * Ignore DDS/ROS internal writers and output topics that are outside the
     * current prototype's tracked topic set.
     */
    if (!registry_value || registry_value->topic_id == TOPIC_UNKNOWN)
    {
        return 0;
    }

    __u32 topic_id = registry_value->topic_id;

    struct writer_key key =
        make_writer_key(
            thread.tgid,
            writer_ptr
        );

    struct writer_topic_context value = {
        .topic_id = topic_id,
        .reserved = 0,
    };

    int err = bpf_map_update_elem(
        &writer_topic_by_key,
        &key,
        &value,
        BPF_ANY
    );

    if (err != 0)
    {
        bpf_printk(
            "PROV_WRITER_TOPIC_SET_FAIL tgid=%u err=%d",
            thread.tgid,
            err
        );
        return 0;
    }

    bpf_printk(
        "PROV_WRITER_TOPIC_SET writer=%lx topic=%u",
        writer_ptr,
            topic_id
    );

    return 0;
}

/*
 * Fast DDS 2.14.6:
 *
 * StatefulWriter::unsent_change_added_to_history(
 *     CacheChange_t*,
 *     steady_clock::time_point const&
 * )
 *
 * ARM64:
 *   x0 = StatefulWriter* this
 *   x1 = CacheChange_t*
 *
 * At this point the CacheChange_t already contains the Writer GUID and
 * Sequence Number (verified independently on the experiment host).
 *
 * This is the terminal point of this provenance module:
 *
 *   CallbackInstanceID
 *        + output TopicID
 *        + (Writer GUID, Sequence Number)
 *             |
 *             v
 *   sample_prov[(GUID, Seq)] = {CallbackInstanceID, TopicID}
 *
 * There is deliberately NO sendmsg hook and NO ALLOW/DENY decision here.
 */
SEC("uprobe/stateful_unsent")
int trace_stateful_unsent(
    struct pt_regs *ctx)
{
    struct thread_key thread =
        current_thread_key();

    if (!is_target_tgid(thread.tgid))
    {
        return 0;
    }

    __u64 writer_ptr =
        (__u64)PT_REGS_PARM1(ctx);

    __u64 change_ptr =
        (__u64)PT_REGS_PARM2(ctx);

    if (writer_ptr == 0 || change_ptr == 0)
    {
        return 0;
    }

    struct callback_instance_context *active_instance =
        bpf_map_lookup_elem(
            &active_callback_instance_by_thread,
            &thread
        );

    if (!active_instance)
    {
        /*
         * The sample was not produced while a configured callback instance
         * was active. No trusted callback provenance is asserted.
         */
        return 0;
    }

    struct writer_key writer_key =
        make_writer_key(
            thread.tgid,
            writer_ptr
        );

    struct writer_topic_context *writer_topic =
        bpf_map_lookup_elem(
            &writer_topic_by_key,
            &writer_key
        );

    if (!writer_topic ||
        writer_topic->topic_id == TOPIC_UNKNOWN)
    {
        bpf_printk(
            "PROV_SAMPLE_SKIP writer=%lx no_topic",
            writer_ptr
        );
        return 0;
    }

    struct sample_identity_key identity = {};
    struct sample_provenance_value provenance = {};

    long guid_err = bpf_probe_read_user(
        identity.writer_guid,
        sizeof(identity.writer_guid),
        (const void *)(
            change_ptr +
            CACHECHANGE_WRITER_GUID_OFFSET
        )
    );

    if (guid_err != 0)
    {
        bpf_printk(
            "PROV_GUID_READ_FAIL err=%ld",
            guid_err
        );
        return 0;
    }

    struct
    {
        __s32 high;
        __u32 low;
    } sequence = {};

    long seq_err = bpf_probe_read_user(
        &sequence,
        sizeof(sequence),
        (const void *)(
            change_ptr +
            CACHECHANGE_SEQUENCE_OFFSET
        )
    );

    if (seq_err != 0)
    {
        bpf_printk(
            "PROV_SEQ_READ_FAIL err=%ld",
            seq_err
        );
        return 0;
    }

    identity.seq_high = sequence.high;
    identity.seq_low = sequence.low;

    provenance.callback_instance_id =
        active_instance->callback_instance_id;

    provenance.topic_id =
        writer_topic->topic_id;

    int err = bpf_map_update_elem(
        &sample_prov,
        &identity,
        &provenance,
        BPF_ANY
    );

    if (err != 0)
    {
        bpf_printk(
            "PROV_SAMPLE_SET_FAIL err=%d",
            err
        );
        return 0;
    }

    bpf_printk(
        "PROV_SAMPLE_SET cb=%u topic=%u",
        provenance.callback_instance_id,
        provenance.topic_id
    );

    bpf_printk(
        "PROV_SAMPLE_SEQ high=%d low=%u",
        identity.seq_high,
        identity.seq_low
    );

    return 0;
}
