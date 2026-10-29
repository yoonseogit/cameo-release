#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/Expr.h"
#include "clang/AST/ExprCXX.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/Diagnostic.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;

namespace
{

llvm::cl::OptionCategory PolicyGenCategory("ROS 2 Source Policy Generator options");
llvm::cl::opt<std::string> OutputPath(
    "output",
    llvm::cl::desc("Output enforcement policy YAML path"),
    llvm::cl::value_desc("path"),
    llvm::cl::init("enforcement_policy.yaml"),
    llvm::cl::cat(PolicyGenCategory));
llvm::cl::opt<std::string> ManifestOutputPath(
    "manifest-output",
    llvm::cl::desc("Output runtime identity manifest YAML path"),
    llvm::cl::value_desc("path"),
    llvm::cl::init("runtime_manifest.yaml"),
    llvm::cl::cat(PolicyGenCategory));

struct PublisherRecord
{
    std::string symbol;
    std::string topic;
    std::string file;
    unsigned line{};
};

struct SubscriptionRecord
{
    std::string input_topic;
    std::string callback_key;
    std::string callback_display;
    std::string file;
    unsigned line{};
};

struct PublishRecord
{
    std::string callback_key;
    std::string callback_display;
    std::string publisher_symbol;
    std::string file;
    unsigned line{};
};

struct UnresolvedRecord
{
    std::string kind;
    std::string detail;
    std::string file;
    unsigned line{};
};

struct State
{
    std::vector<PublisherRecord> publishers;
    std::vector<SubscriptionRecord> subscriptions;
    std::vector<PublishRecord> publishes;
    std::vector<UnresolvedRecord> unresolved;
};

State g_state;

std::string normalize_ros_topic(std::string topic)
{
    const auto first = topic.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
    {
        return {};
    }

    const auto last = topic.find_last_not_of(" \t\r\n");
    topic = topic.substr(first, last - first + 1);

    if (topic.front() != '/')
    {
        topic.insert(topic.begin(), '/');
    }

    return topic;
}

std::string yaml_quote(const std::string& s)
{
    std::string out = "\"";
    for (char c : s)
    {
        if (c == '\\' || c == '"')
        {
            out.push_back('\\');
        }
        out.push_back(c);
    }
    out += "\"";
    return out;
}

std::string identity_manifest_id(
    const std::vector<std::tuple<uint32_t, std::string, unsigned>>& callbacks,
    const std::map<std::string, uint32_t>& topics)
{
    // Non-cryptographic consistency identifier. The frozen artifact SHA-256
    // remains the integrity mechanism; this ID prevents accidental mixing of
    // a manifest and enforcement policy from different generator runs.
    uint64_t hash = 1469598103934665603ULL;
    const auto add = [&hash](const std::string& value) {
        for (const unsigned char c : value)
        {
            hash ^= c;
            hash *= 1099511628211ULL;
        }
        hash ^= 0xffU;
        hash *= 1099511628211ULL;
    };
    for (const auto& [id, input, instance] : callbacks)
    {
        add(std::to_string(id));
        add(input);
        add(std::to_string(instance));
    }
    for (const auto& [topic, id] : topics)
    {
        add(std::to_string(id));
        add(topic);
    }
    std::ostringstream out;
    out << std::hex << std::setw(16) << std::setfill('0') << hash;
    return out.str();
}

std::string loc_file(const SourceManager& sm, SourceLocation loc)
{
    loc = sm.getExpansionLoc(loc);
    const char* name = sm.getFilename(loc).data();
    return name ? std::string(name) : std::string("<unknown>");
}

unsigned loc_line(const SourceManager& sm, SourceLocation loc)
{
    return sm.getSpellingLineNumber(sm.getExpansionLoc(loc));
}

bool is_main_file(const SourceManager& sm, SourceLocation loc)
{
    return sm.isWrittenInMainFile(sm.getExpansionLoc(loc));
}

const Expr* strip_expr(const Expr* e)
{
    if (!e)
    {
        return nullptr;
    }
    return e->IgnoreParenImpCasts();
}

std::optional<std::string> string_literal_value(const Expr* e)
{
    e = strip_expr(e);
    if (const auto* s = dyn_cast_or_null<StringLiteral>(e))
    {
        return s->getString().str();
    }

    // Handle std::string("/topic") and similar wrappers containing a literal.
    if (const auto* ctor = dyn_cast_or_null<CXXConstructExpr>(e))
    {
        for (const Expr* arg : ctor->arguments())
        {
            if (auto v = string_literal_value(arg))
            {
                return v;
            }
        }
    }

    if (const auto* materialized = dyn_cast_or_null<MaterializeTemporaryExpr>(e))
    {
        return string_literal_value(materialized->getSubExpr());
    }

    if (const auto* bind_temp = dyn_cast_or_null<CXXBindTemporaryExpr>(e))
    {
        return string_literal_value(bind_temp->getSubExpr());
    }

    return std::nullopt;
}

std::string value_decl_key(const ValueDecl* decl)
{
    if (!decl)
    {
        return {};
    }
    if (const auto* named = dyn_cast<NamedDecl>(decl))
    {
        std::string q = named->getQualifiedNameAsString();
        if (!q.empty())
        {
            return q;
        }
        return named->getNameAsString();
    }
    return {};
}

class FirstStorageDeclVisitor : public RecursiveASTVisitor<FirstStorageDeclVisitor>
{
public:
    bool VisitMemberExpr(MemberExpr* e)
    {
        if (!result_)
        {
            if (const auto* vd = dyn_cast<ValueDecl>(e->getMemberDecl()))
            {
                if (isa<FieldDecl>(vd) || isa<VarDecl>(vd) || isa<ParmVarDecl>(vd))
                {
                    result_ = vd;
                }
            }
        }
        return true;
    }

    bool VisitDeclRefExpr(DeclRefExpr* e)
    {
        if (!result_)
        {
            if (const auto* vd = dyn_cast<ValueDecl>(e->getDecl()))
            {
                if (isa<FieldDecl>(vd) || isa<VarDecl>(vd) || isa<ParmVarDecl>(vd))
                {
                    result_ = vd;
                }
            }
        }
        return true;
    }

    const ValueDecl* result() const { return result_; }

private:
    const ValueDecl* result_ = nullptr;
};

std::optional<std::string> storage_symbol_from_expr(const Expr* e)
{
    e = strip_expr(e);
    if (!e)
    {
        return std::nullopt;
    }

    FirstStorageDeclVisitor visitor;
    visitor.TraverseStmt(const_cast<Expr*>(e));
    if (const ValueDecl* vd = visitor.result())
    {
        std::string key = value_decl_key(vd);
        if (!key.empty())
        {
            return key;
        }
    }
    return std::nullopt;
}

std::optional<std::string> storage_symbol_for_call(
    const Expr* call,
    ASTContext& ctx)
{
    DynTypedNode node = DynTypedNode::create(*call);

    // Walk a few parents to cover implicit casts, temporaries, shared_ptr operator=, etc.
    for (int depth = 0; depth < 12; ++depth)
    {
        auto parents = ctx.getParents(node);
        if (parents.empty())
        {
            break;
        }

        const DynTypedNode& p = parents[0];

        if (const auto* vd = p.get<VarDecl>())
        {
            std::string key = value_decl_key(vd);
            if (!key.empty())
            {
                return key;
            }
        }

        if (const auto* bo = p.get<BinaryOperator>())
        {
            if (bo->isAssignmentOp())
            {
                if (auto key = storage_symbol_from_expr(bo->getLHS()))
                {
                    return key;
                }
            }
        }

        if (const auto* op = p.get<CXXOperatorCallExpr>())
        {
            if (op->getOperator() == OO_Equal && op->getNumArgs() >= 1)
            {
                if (auto key = storage_symbol_from_expr(op->getArg(0)))
                {
                    return key;
                }
            }
        }

        node = p;
    }

    return std::nullopt;
}

std::string function_key(const FunctionDecl* fd)
{
    if (!fd)
    {
        return {};
    }
    std::string q = fd->getQualifiedNameAsString();
    if (!q.empty())
    {
        return q;
    }
    return fd->getNameAsString();
}

const FunctionDecl* enclosing_function(const Stmt* stmt, ASTContext& ctx)
{
    DynTypedNode node = DynTypedNode::create(*stmt);
    for (int depth = 0; depth < 24; ++depth)
    {
        auto parents = ctx.getParents(node);
        if (parents.empty())
        {
            return nullptr;
        }
        const DynTypedNode& p = parents[0];
        if (const auto* fd = p.get<FunctionDecl>())
        {
            return fd;
        }
        node = p;
    }
    return nullptr;
}

class CallbackTargetVisitor : public RecursiveASTVisitor<CallbackTargetVisitor>
{
public:
    bool VisitLambdaExpr(LambdaExpr* e)
    {
        if (!lambda_)
        {
            lambda_ = e;
        }
        return true;
    }

    bool VisitUnaryOperator(UnaryOperator* u)
    {
        if (method_ || u->getOpcode() != UO_AddrOf)
        {
            return true;
        }

        const Expr* sub = strip_expr(u->getSubExpr());
        if (const auto* dre = dyn_cast_or_null<DeclRefExpr>(sub))
        {
            method_ = dyn_cast<CXXMethodDecl>(dre->getDecl());
        }
        else if (const auto* me = dyn_cast_or_null<MemberExpr>(sub))
        {
            method_ = dyn_cast<CXXMethodDecl>(me->getMemberDecl());
        }
        return true;
    }

    bool VisitDeclRefExpr(DeclRefExpr* e)
    {
        if (!method_)
        {
            method_ = dyn_cast<CXXMethodDecl>(e->getDecl());
        }
        return true;
    }

    const CXXMethodDecl* method() const { return method_; }
    const LambdaExpr* lambda() const { return lambda_; }

private:
    const CXXMethodDecl* method_ = nullptr;
    const LambdaExpr* lambda_ = nullptr;
};

struct CallbackTarget
{
    std::string key;
    std::string display;
};

std::optional<CallbackTarget> callback_target_from_subscription(
    const CXXMemberCallExpr* call,
    ASTContext& ctx,
    const SourceManager& sm)
{
    // create_subscription(topic, qos, callback, ...)
    // Search all arguments after the QoS argument so overload details do not matter.
    for (unsigned i = 2; i < call->getNumArgs(); ++i)
    {
        const Expr* arg = call->getArg(i);
        CallbackTargetVisitor visitor;
        visitor.TraverseStmt(const_cast<Expr*>(arg));

        if (const LambdaExpr* lambda = visitor.lambda())
        {
            const CXXMethodDecl* op = lambda->getCallOperator();
            if (op)
            {
                const unsigned line = loc_line(sm, lambda->getBeginLoc());
                std::ostringstream display;
                display << "<lambda@" << line << ">";
                return CallbackTarget{function_key(op), display.str()};
            }
        }

        if (const CXXMethodDecl* method = visitor.method())
        {
            return CallbackTarget{function_key(method), method->getNameAsString()};
        }
    }
    return std::nullopt;
}

std::optional<std::string> publisher_symbol_from_publish_call(
    const CXXMemberCallExpr* call)
{
    const Expr* obj = call->getImplicitObjectArgument();
    if (!obj)
    {
        return std::nullopt;
    }
    return storage_symbol_from_expr(obj);
}

class PolicyCallback : public MatchFinder::MatchCallback
{
public:
    enum class Kind
    {
        Publisher,
        Subscription,
        Publish
    };

    explicit PolicyCallback(Kind kind) : kind_(kind) {}

    void run(const MatchFinder::MatchResult& result) override
    {
        ASTContext* ctx = result.Context;
        if (!ctx)
        {
            return;
        }
        const SourceManager& sm = ctx->getSourceManager();

        if (kind_ == Kind::Publisher)
        {
            const auto* call = result.Nodes.getNodeAs<CXXMemberCallExpr>("publisher_call");
            if (!call || !is_main_file(sm, call->getBeginLoc()))
            {
                return;
            }

            const std::string file = loc_file(sm, call->getBeginLoc());
            const unsigned line = loc_line(sm, call->getBeginLoc());

            if (call->getNumArgs() < 1)
            {
                g_state.unresolved.push_back({"PUBLISHER", "create_publisher has no topic argument", file, line});
                return;
            }

            auto topic = string_literal_value(call->getArg(0));
            auto symbol = storage_symbol_for_call(call, *ctx);
            if (!topic)
            {
                g_state.unresolved.push_back({"PUBLISHER_TOPIC", "topic is not a compile-time string literal", file, line});
                return;
            }

            *topic = normalize_ros_topic(*topic);
            if (topic->empty())
            {
                g_state.unresolved.push_back({"PUBLISHER_TOPIC", "topic is empty after normalization", file, line});
                return;
            }
            if (!symbol)
            {
                g_state.unresolved.push_back({"PUBLISHER_STORAGE", "could not identify variable/member receiving create_publisher()", file, line});
                return;
            }

            g_state.publishers.push_back({*symbol, *topic, file, line});
            return;
        }

        if (kind_ == Kind::Subscription)
        {
            const auto* call = result.Nodes.getNodeAs<CXXMemberCallExpr>("subscription_call");
            if (!call || !is_main_file(sm, call->getBeginLoc()))
            {
                return;
            }

            const std::string file = loc_file(sm, call->getBeginLoc());
            const unsigned line = loc_line(sm, call->getBeginLoc());

            if (call->getNumArgs() < 3)
            {
                g_state.unresolved.push_back({"SUBSCRIPTION", "create_subscription has fewer than 3 arguments", file, line});
                return;
            }

            auto input = string_literal_value(call->getArg(0));
            if (!input)
            {
                g_state.unresolved.push_back({"SUBSCRIPTION_TOPIC", "input topic is not a compile-time string literal", file, line});
                return;
            }

            *input = normalize_ros_topic(*input);
            if (input->empty())
            {
                g_state.unresolved.push_back({"SUBSCRIPTION_TOPIC", "input topic is empty after normalization", file, line});
                return;
            }

            auto callback = callback_target_from_subscription(call, *ctx, sm);
            if (!callback)
            {
                g_state.unresolved.push_back({"CALLBACK_BINDING", "could not resolve subscription callback (supported: std::bind/member callback/lambda)", file, line});
                return;
            }

            g_state.subscriptions.push_back({*input, callback->key, callback->display, file, line});
            return;
        }

        const auto* call = result.Nodes.getNodeAs<CXXMemberCallExpr>("publish_call");
        if (!call || !is_main_file(sm, call->getBeginLoc()))
        {
            return;
        }

        const std::string file = loc_file(sm, call->getBeginLoc());
        const unsigned line = loc_line(sm, call->getBeginLoc());
        const FunctionDecl* fd = enclosing_function(call, *ctx);
        if (!fd)
        {
            g_state.unresolved.push_back({"PUBLISH_CALL", "publish() is not enclosed by a resolvable function", file, line});
            return;
        }

        auto publisher = publisher_symbol_from_publish_call(call);
        if (!publisher)
        {
            g_state.unresolved.push_back({"PUBLISHER_REFERENCE", "could not resolve publisher object used by publish()", file, line});
            return;
        }

        std::string cb_key = function_key(fd);
        std::string cb_display = fd->getNameAsString();
        if (const auto* md = dyn_cast<CXXMethodDecl>(fd))
        {
            if (md->getParent() && md->getParent()->isLambda())
            {
                std::ostringstream ss;
                ss << "<lambda@" << loc_line(sm, md->getBeginLoc()) << ">";
                cb_display = ss.str();
            }
        }

        g_state.publishes.push_back({cb_key, cb_display, *publisher, file, line});
    }

private:
    Kind kind_;
};

void sort_and_unique_state()
{
    auto pub_less = [](const PublisherRecord& a, const PublisherRecord& b) {
        return std::tie(a.symbol, a.topic, a.file, a.line) < std::tie(b.symbol, b.topic, b.file, b.line);
    };
    std::sort(g_state.publishers.begin(), g_state.publishers.end(), pub_less);
    g_state.publishers.erase(std::unique(g_state.publishers.begin(), g_state.publishers.end(),
        [](const auto& a, const auto& b) { return a.symbol == b.symbol && a.topic == b.topic; }), g_state.publishers.end());

    std::sort(g_state.subscriptions.begin(), g_state.subscriptions.end(), [](const auto& a, const auto& b) {
        return std::tie(a.input_topic, a.callback_key, a.file, a.line) < std::tie(b.input_topic, b.callback_key, b.file, b.line);
    });
    g_state.subscriptions.erase(std::unique(g_state.subscriptions.begin(), g_state.subscriptions.end(),
        [](const auto& a, const auto& b) { return a.input_topic == b.input_topic && a.callback_key == b.callback_key && a.file == b.file && a.line == b.line; }), g_state.subscriptions.end());

    std::sort(g_state.publishes.begin(), g_state.publishes.end(), [](const auto& a, const auto& b) {
        return std::tie(a.callback_key, a.publisher_symbol, a.file, a.line) < std::tie(b.callback_key, b.publisher_symbol, b.file, b.line);
    });
    g_state.publishes.erase(std::unique(g_state.publishes.begin(), g_state.publishes.end(),
        [](const auto& a, const auto& b) { return a.callback_key == b.callback_key && a.publisher_symbol == b.publisher_symbol; }), g_state.publishes.end());
}

int emit_policy()
{
    sort_and_unique_state();

    std::map<std::string, std::string> publisher_topics;
    for (const auto& p : g_state.publishers)
    {
        auto it = publisher_topics.find(p.symbol);
        if (it != publisher_topics.end() && it->second != p.topic)
        {
            g_state.unresolved.push_back({"PUBLISHER_ALIAS", "same publisher symbol resolved to multiple topics: " + p.symbol, p.file, p.line});
        }
        else
        {
            publisher_topics[p.symbol] = p.topic;
        }
    }

    std::map<std::string, std::set<std::string>> callback_outputs;
    for (const auto& p : g_state.publishes)
    {
        auto it = publisher_topics.find(p.publisher_symbol);
        if (it == publisher_topics.end())
        {
            g_state.unresolved.push_back({"PUBLISH_TARGET", "publish() uses unknown publisher symbol: " + p.publisher_symbol, p.file, p.line});
            continue;
        }
        callback_outputs[p.callback_key].insert(it->second);
    }

    // Fail closed if a discovered subscription callback has no directly resolved publish path.
    // A callback with genuinely no publish() is valid and simply needs no output allowlist, so
    // we report it but do not fail. The security-relevant failure is an unresolved construct above.

    std::cout << "========================================\n";
    std::cout << "ROS 2 Source Policy Generator\n";
    std::cout << "Mode: Clang AST / benign-source allowlist\n";
    std::cout << "========================================\n";

    for (const auto& p : g_state.publishers)
    {
        std::cout << "[PUBLISHER] symbol=" << p.symbol << " topic=" << p.topic
                  << " @" << p.file << ':' << p.line << '\n';
    }
    for (const auto& s : g_state.subscriptions)
    {
        std::cout << "[SUBSCRIPTION] topic=" << s.input_topic
                  << " callback=" << s.callback_display
                  << " @" << s.file << ':' << s.line << '\n';
    }
    for (const auto& p : g_state.publishes)
    {
        std::cout << "[PUBLISH_CALL] callback=" << p.callback_display
                  << " publisher=" << p.publisher_symbol
                  << " @" << p.file << ':' << p.line << '\n';
    }

    if (!g_state.unresolved.empty())
    {
        std::cerr << "\n[POLICY_GENERATION_FAILED]\n";
        for (const auto& u : g_state.unresolved)
        {
            std::cerr << "  " << u.kind << " @" << u.file << ':' << u.line
                      << " - " << u.detail << '\n';
        }
        std::cerr << "Refusing to emit an incomplete security allowlist.\n";
        return 2;
    }

    struct PolicyEntry
    {
        uint32_t callback_instance_id{};
        std::string input;
        unsigned instance{};
        std::string callback;
        std::set<std::string> outputs;
    };

    std::vector<PolicyEntry> entries;
    std::map<std::string, unsigned> per_input_instance;

    for (const auto& s : g_state.subscriptions)
    {
        unsigned instance = ++per_input_instance[s.input_topic];
        if (instance > 1)
        {
            std::cerr << "[DUPLICATE_INPUT_TOPIC] normalized input topic "
                      << yaml_quote(s.input_topic)
                      << " is used by more than one subscription; "
                         "instance>1 is unsupported by the runtime tracker\n";
            std::cerr << "Refusing to emit runtime manifest or enforcement policy.\n";
            return 2;
        }
        PolicyEntry e;
        e.callback_instance_id = static_cast<uint32_t>(entries.size() + 1);
        e.input = s.input_topic;
        e.instance = instance;
        e.callback = s.callback_display;
        auto it = callback_outputs.find(s.callback_key);
        if (it != callback_outputs.end())
        {
            e.outputs = it->second;
        }
        entries.push_back(std::move(e));
    }

    std::map<std::string, uint32_t> topic_ids;
    for (const auto& publisher : g_state.publishers)
    {
        topic_ids.emplace(publisher.topic, 0);
    }
    uint32_t next_topic_id = 1;
    for (auto& [topic, id] : topic_ids)
    {
        static_cast<void>(topic);
        id = next_topic_id++;
    }

    std::vector<std::tuple<uint32_t, std::string, unsigned>> callback_identities;
    for (const auto& e : entries)
    {
        callback_identities.emplace_back(e.callback_instance_id, e.input, e.instance);
    }
    const std::string manifest_id = identity_manifest_id(callback_identities, topic_ids);

    std::ofstream manifest(ManifestOutputPath);
    if (!manifest)
    {
        std::cerr << "Could not open runtime manifest file: " << ManifestOutputPath << '\n';
        return 3;
    }

    manifest << "version: 1\n";
    manifest << "artifact: runtime_manifest\n";
    manifest << "manifest_id: " << yaml_quote(manifest_id) << "\n";
    manifest << "callback_instances:\n";
    for (const auto& e : entries)
    {
        manifest << "  - callback_instance_id: " << e.callback_instance_id << "\n";
        manifest << "    selector:\n";
        manifest << "      input_topic: " << yaml_quote(e.input) << "\n";
        manifest << "      instance: " << e.instance << "\n";
        manifest << "    callback_hint: " << yaml_quote(e.callback) << "\n";
    }
    if (topic_ids.empty())
    {
        manifest << "topics: []\n";
    }
    else
    {
        manifest << "topics:\n";
        for (const auto& [topic, id] : topic_ids)
        {
            const std::string normalized = topic.empty() || topic.front() == '/'
                ? topic
                : "/" + topic;
            manifest << "  - topic_id: " << id << "\n";
            manifest << "    ros_name: " << yaml_quote(normalized) << "\n";
            manifest << "    dds_name: " << yaml_quote("rt" + normalized) << "\n";
        }
    }
    manifest.close();

    std::ofstream out(OutputPath);
    if (!out)
    {
        std::cerr << "Could not open output file: " << OutputPath << '\n';
        return 3;
    }

    out << "version: 1\n";
    out << "artifact: enforcement_policy\n";
    out << "manifest_id: " << yaml_quote(manifest_id) << "\n";
    out << "policy_mode: allowlist\n";
    std::size_t allow_count = 0;
    for (const auto& e : entries)
    {
        allow_count += e.outputs.size();
    }
    out << (allow_count == 0 ? "allow: []\n" : "allow:\n");

    for (const auto& e : entries)
    {
        for (const auto& topic : e.outputs)
        {
            const auto topic_it = topic_ids.find(topic);
            if (topic_it == topic_ids.end())
            {
                std::cerr << "Internal error: output topic missing from runtime manifest: "
                          << topic << '\n';
                return 4;
            }
            out << "  - callback_instance_id: " << e.callback_instance_id << "\n";
            out << "    topic_id: " << topic_it->second << "\n";
        }
    }

    out.close();

    std::cout << "\n[POLICY_RELATIONS]\n";
    for (const auto& e : entries)
    {
        if (e.outputs.empty())
        {
            std::cout << "  " << e.input << " [instance " << e.instance << "] -> <no publish>\n";
        }
        else
        {
            for (const auto& output : e.outputs)
            {
                std::cout << "  " << e.input << " [instance " << e.instance << "] -> " << output << '\n';
            }
        }
    }

    std::cout << "\n[RUNTIME_MANIFEST_GENERATED] " << ManifestOutputPath << '\n';
    std::cout << "[ENFORCEMENT_POLICY_GENERATED] " << OutputPath << '\n';
    return 0;
}

} // namespace

int main(int argc, const char** argv)
{
    auto expectedParser = CommonOptionsParser::create(argc, argv, PolicyGenCategory);
    if (!expectedParser)
    {
        llvm::errs() << expectedParser.takeError();
        return 1;
    }

    CommonOptionsParser& options = expectedParser.get();
    ClangTool tool(options.getCompilations(), options.getSourcePathList());

    PolicyCallback publisherCb(PolicyCallback::Kind::Publisher);
    PolicyCallback subscriptionCb(PolicyCallback::Kind::Subscription);
    PolicyCallback publishCb(PolicyCallback::Kind::Publish);

    MatchFinder finder;

    finder.addMatcher(
        cxxMemberCallExpr(
            callee(cxxMethodDecl(hasName("create_publisher"))))
            .bind("publisher_call"),
        &publisherCb);

    finder.addMatcher(
        cxxMemberCallExpr(
            callee(cxxMethodDecl(hasName("create_subscription"))))
            .bind("subscription_call"),
        &subscriptionCb);

    finder.addMatcher(
        cxxMemberCallExpr(
            callee(cxxMethodDecl(hasName("publish"))))
            .bind("publish_call"),
        &publishCb);

    const int rc = tool.run(newFrontendActionFactory(&finder).get());
    if (rc != 0)
    {
        std::cerr << "ClangTool failed with rc=" << rc << '\n';
        return rc;
    }

    return emit_policy();
}
