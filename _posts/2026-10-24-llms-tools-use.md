---
layout: post
title: "Can LLMs Invoke Tools It Was Never Allowed to Use?"
categories: [llm, llm security, AI Security, spring ai]
permalink: /llm-tools-use-cve-2026-59318/
---

In this article, we'll understand how tool resolution can cross authorization boundaries, look at CVE-2026-59318 in Spring AI, reproduce the issue, and examine the fix. We'll also explore what this means for tool security in AI agent systems.

{: .no_toc }

* TOC
{:toc}


## Are Tool Definitions Really a Security Boundary?

With LLMs becoming a part of almost everything these days, applications are doing much more than just answering questions. They can search documents, retrieve information, and even perform actions on behalf of users through something called *tool calling*.

Let's say we have an AI assistant with two tools: `searchDocument`, which searches for documents, and `deleteDocument`, which deletes them. For a regular user, we only make `searchDocument` available to the LLM, while `deleteDocument` remains in the application's backend.

So, the LLM shouldn't be able to delete documents, right?

But what if it somehow generates a call to `deleteDocument` anyway? Maybe a user asks it to delete something, or maybe it comes across a malicious instruction while reading a document. Would the application reject it because the tool wasn't provided to the LLM, or would it execute it simply because the function exists in the backend?

**This raises an interesting question: Is hiding a tool from an LLM enough to prevent it from being executed, or are we treating tool definitions as a security boundary?**

## How Does LLM Tool Calling Actually Work?

Before getting into the security side of things, let's understand how tool calling works.

An LLM cannot directly execute a function in your application. Instead, the application provides the LLM with a list of available tools, along with their names, descriptions, and expected parameters. Based on the user's request, the LLM decides whether to use a tool and generates a structured response containing the tool name and arguments.

For example, if a user asks our document assistant to find a report, the LLM might generate something like this:

```json
{
  "name": "searchDocument",
  "arguments": {
    "query": "annual financial report"
  }
}
```

The application receives this response, finds the corresponding function, executes it, and sends the result back to the LLM so it can respond to the user.

We can see a similar concept in tools like Claude Code. When we ask Claude Code to read a file or run a command, the model doesn't directly access our filesystem or terminal. It requests a tool call, and the surrounding application handles its execution, subject to its permission settings.

The important thing to understand here is that **the LLM only requests a tool call. The application is responsible for deciding whether that tool should actually be executed.**

And this is exactly where things can go wrong.

## What Happens When an LLM Calls a Tool It Wasn't Given?

When an application sends a request to an LLM, it usually includes a list of tools the model can use. But that list doesn't necessarily contain every tool registered in the application.

Let's go back to our document assistant. Suppose the application has these two functions:

```java
@Tool(description = "Search for documents")
public String searchDocument(String query) {
    return "Found documents matching: " + query;
}

@Tool(description = "Delete a document")
public String deleteDocument(String documentId) {
    return "Deleted document: " + documentId;
}
```

For a regular user, the application only makes `searchDocument` available to the LLM. The `deleteDocument` function still exists, but it isn't included in the tools provided for that request.

Now, suppose the LLM somehow returns the following tool call:

```json
{
  "name": "deleteDocument",
  "arguments": {
    "documentId": "123"
  }
}
```

What happens next depends entirely on how the application handles that response.

If the application only looks for tools in the current request's allowed list, the call should be rejected. But if it searches a broader registry of tools, it might find `deleteDocument` and execute it anyway.

And this isn't just a hypothetical problem. A real-world example of this issue can be found in Spring AI, a Java framework that helps developers integrate LLMs into their applications.

## A Closer Look at Spring AI's Tool-Calling Mechanism

On August 20, 2026, a vulnerability ([CVE-2026-59318](https://spring.io/security/cve-2026-59318)) was publicly disclosed in Spring AI, where a tool that wasn't made available to the LLM for a particular request could still be executed. This happened because Spring AI could look up the requested tool from a broader tool registry when it couldn't find it among the tools provided for that request. 

To understand why this happened, we first need to look at how Spring AI registers, resolves, and executes tools.
Spring AI uses a few important components to handle tool calling:

- `ToolCallback` — Represents an executable tool, including its definition and the logic needed to invoke it.
- `ToolCallbackResolver` — Looks up a registered tool using its name.
- `DefaultToolCallingManager` — Handles tool calls returned by the LLM, resolves the corresponding callbacks, and executes them.

### Tracing Tool Execution in Spring AI 2.0.0

The interesting part is inside `DefaultToolCallingManager.java`, specifically the `executeToolCalls()` method. This method receives the model's response, extracts the requested tool calls, finds their corresponding Java callbacks, and executes them.

First, Spring AI retrieves the tool calls returned by the model:

```java
for (AssistantMessage.ToolCall toolCall : assistantMessage.getToolCalls()) {
    String toolName = toolCall.name();
    String toolInputArguments = toolCall.arguments();
}
```

Here, `toolName` is the name of the function the LLM wants to invoke, while `toolInputArguments` contains the arguments supplied by the model.

For example, if the model requests `searchDocument` with a search query, Spring AI needs to find the Java callback associated with that name before executing it.

The tool lookup happens through the following code in Spring AI 2.0.0:

```java
ToolCallback toolCallback = toolCallbacks.stream()
    .filter(tool -> toolName.equals(tool.getToolDefinition().name()))
    .findFirst()
    .orElseGet(() -> this.toolCallbackResolver.resolve(toolName));
```

Spring AI first searches the `toolCallbacks` list for a tool whose name matches the one requested by the LLM.

If it finds a match, that callback is selected for execution.

But what happens if the tool isn't in the list?

Instead of stopping there, Spring AI calls:

```java
this.toolCallbackResolver.resolve(toolName)
```

This is a fallback mechanism that tries to find the tool by name through the application's configured resolver.

Let's use our document assistant again. Suppose only `searchDocument` was provided for the current request, but `deleteDocument` is also registered in the broader resolver.

If the model returns a call to `deleteDocument`, Spring AI won't find it in the request's callback list. However, the fallback resolver may still find it.

And if it does, the manager can continue with the resolved callback.

**Spring AI was checking whether it could find the requested tool, but it wasn't restricting the fallback lookup to the tools available for that particular request.** Spring AI's fallback resolver could find and execute a tool even when it wasn't included in the callbacks available to the current request.

Now suppose the LLM generates a call to `deleteDocument`. In Spring AI 2.0.0, the following line becomes important:

```java
.orElseGet(() -> this.toolCallbackResolver.resolve(toolName));
```

Since `deleteDocument` isn't present in the request's `toolCallbacks`, Spring AI falls back to the resolver. If the resolver knows about `deleteDocument`, it returns the corresponding `ToolCallback`.

The manager can then execute the resolved callback through the normal tool-execution path:

```java
toolCallback.call(finalToolInputArguments, toolContext);
```

Spring AI doesn't check whether the resolved tool was actually made available to the current request before proceeding with its execution. This means that **a tool being registered in the application could be enough for it to be executed, even when it wasn't supposed to be available to that particular request.**

The issue comes down to three things that shouldn't be confused:

- **Tool visibility:** The tools that are advertised to the LLM.
- **Tool resolution:** The tools that the application can find by name.
- **Tool authorization:** The tools that the current user or request is actually permitted to execute.

In this case, the fallback mechanism allowed tool resolution to bypass the restriction implied by the request-specific tool list.

Of course, this doesn't mean every Spring AI application using version 2.0.0 was automatically vulnerable to unauthorized actions. The impact depends on which tools were registered in the resolver and whether those tools performed their own authorization checks.

But for applications relying only on the tools provided to the LLM as an access-control mechanism, this behavior could become a problem.

**This meant that simply leaving a tool out of the list provided to the LLM wasn't enough to prevent Spring AI from executing it.** The authorization boundary needs to be enforced when the tool is executed, not just when its definition is sent to the model.

### Reproducing the Issue

To verify the behavior, I created a small Maven project using Spring AI 2.0.0. Instead of connecting to a real LLM, I simulated an LLM response and passed it directly to `DefaultToolCallingManager`. 

**Setting Up the Tools**

I defined two tools: `searchDocument` and `deleteDocument`.

```java
public static class DocumentTools {

    @Tool(description = "Search documents")
    public String searchDocument(String query) {
        return "Found: " + query;
    }

    @Tool(description = "Delete a document")
    public String deleteDocument(String documentId) {
        deletionExecuted.set(true);
        System.out.println("[!] deleteDocument executed!");
        return "Mock deletion: " + documentId;
    }
}
```

The deletion is simulated. An `AtomicBoolean` tracks whether the method actually executes.

Next, I registered both tools in a `StaticToolCallbackResolver`, but made only `searchDocument` available to the current request.

```java
ToolCallback[] callbacks = MethodToolCallbackProvider.builder()
        .toolObjects(new DocumentTools())
        .build()
        .getToolCallbacks();

var resolver = new StaticToolCallbackResolver(
        Arrays.asList(callbacks)
);

ToolCallback searchCallback = Arrays.stream(callbacks)
        .filter(cb -> cb.getToolDefinition().name()
                .equals("searchDocument"))
        .findFirst()
        .orElseThrow();

var options = ToolCallingChatOptions.builder()
        .toolCallbacks(searchCallback)
        .build();

Prompt prompt = new Prompt(
        List.of(new UserMessage("Find document 123")),
        options
);
```

At this point, the request exposes only `searchDocument`, while the broader resolver knows about both tools.

**Simulating an Unadvertised Tool Call**

I then constructed a synthetic LLM response requesting `deleteDocument`.

```java
AssistantMessage.ToolCall toolCall =
        new AssistantMessage.ToolCall(
                "call-123",
                "function",
                "deleteDocument",
                "{\"documentId\":\"123\"}"
        );

AssistantMessage message = AssistantMessage.builder()
        .content("")
        .toolCalls(List.of(toolCall))
        .build();

ChatResponse response = new ChatResponse(
        List.of(new Generation(message))
);
```

Finally, I passed the prompt and response to Spring AI's tool-calling manager.

```java
var manager = DefaultToolCallingManager.builder()
        .toolCallbackResolver(resolver)
        .build();

manager.executeToolCalls(prompt, response);
```

**Results: Spring AI 2.0.0 vs. 2.0.1**

With Spring AI 2.0.0, the output was:

```text
Allowed tool: searchDocument
Simulated LLM tool call: deleteDocument
[!] deleteDocument executed!
Deletion executed: true
BUILD SUCCESS
```

Despite `deleteDocument` not being part of the request's callbacks, Spring AI resolved it through the fallback resolver and executed it.

I then changed only the Maven dependency to Spring AI 2.0.1 and ran the same test.

```text
Allowed tool: searchDocument
Simulated LLM tool call: deleteDocument

java.lang.IllegalStateException:
No ToolCallback found for tool name: deleteDocument

BUILD FAILURE
```

This time, Spring AI rejected the tool call. The test failed because it expected the vulnerable behavior, but `deleteDocument` was no longer executed.

The difference is clear: **Spring AI 2.0.0 executed a globally resolvable tool that wasn't available to the request, while 2.0.1 rejected the same call by default.**

### How Did Spring AI Fix This?

In Spring AI 2.0.0, if a tool wasn't found among the callbacks available to the current request, the manager automatically attempted to resolve it through `ToolCallbackResolver`.

```java
// Spring AI 2.0.0
.orElseGet(() -> this.toolCallbackResolver.resolve(toolName));
```

In Spring AI 2.0.1, an additional condition was introduced:

```java
// Spring AI 2.0.1
.orElseGet(() -> this.resolutionFallbackEnabled
        ? this.toolCallbackResolver.resolve(toolName)
        : null);
```

The new `resolutionFallbackEnabled` option is disabled by default. This means Spring AI no longer searches the broader resolver when a requested tool isn't among the current request's callbacks, unless the application explicitly enables that behavior.
If no matching callback is found, the tool call is rejected.
This is exactly what we observed in our PoC. The same `deleteDocument` call that executed in 2.0.0 was rejected in 2.0.1.

## Security Boundaries in AI Agent Architectures

The issue in Spring AI highlights a broader security concern in agentic systems: **tool availability, tool resolution, and tool authorization are separate operations.** Treating them as interchangeable can introduce security risks, particularly when agents interact with multiple tools or external services.

Similar design mistakes can occur in several areas:

**1. Shared Tool Registries**

AI applications may maintain a central registry of tools used by different agents, users, or workflows. If a tool is resolved from this registry without validating the current request's permissions, an agent could execute a tool outside its intended scope.

**2. Dynamic Tool Discovery**

Some agent frameworks dynamically discover tools based on the task or connected services. Filtering the tools advertised to the model does not necessarily restrict which tools the execution layer can invoke. Authorization must be enforced when the tool call is processed.

**3. MCP Integrations**

MCP servers can expose tools with different levels of privilege, such as `readFile`, `writeFile`, and `deleteFile`. Relying solely on tool descriptions, model instructions, or client-side filtering to restrict sensitive operations is insufficient. The MCP server or an appropriate enforcement layer must independently validate permissions before execution.

**4. Multi-Agent Systems**

In systems where agents delegate tasks to other agents, tool calls may cross multiple execution boundaries. A receiving agent should not automatically assume that a delegated tool call is authorized simply because it originated from another agent. Permissions need to be preserved and validated across delegation.

The common security principle is **least privilege enforced at execution time**. An agent should only be able to perform operations explicitly permitted for its current user, task, and execution context, regardless of which tools are discoverable or registered in the application.

## Final Thoughts

An LLM doesn't execute tools on its own. It generates tool calls, and the application decides whether to execute them.

Our PoC showed that Spring AI 2.0.0 could execute a tool that wasn't available to the current request if it was registered in the broader resolver. Although we used a simulated LLM response, the issue highlights an important distinction: hiding a tool from an LLM is not the same as preventing its execution.

Ultimately, tool authorization must be enforced by the application, not assumed from the tools exposed to the model.

## References

- [CVE-2026-59318](https://spring.io/security/cve-2026-59318)
- [Spring AI GitHub](https://github.com/spring-projects/spring-ai/)
