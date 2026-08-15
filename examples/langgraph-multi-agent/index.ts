import { StateGraph, START, END, MemorySaver } from "@langchain/langgraph";
import { ChatOpenAI } from "@langchain/openai";
import { BaseMessage, HumanMessage, AIMessage } from "@langchain/core/messages";
// Mocking Aegis Invariant Kernel for demonstration purposes
import { AegisConfig, protect, detectThreats } from "../../src/aegis-kernel"; // assuming src path

// --- Aegis Security Middleware Setup ---

const aegisConfig: AegisConfig = {
    mode: "enforce",
    policies: [
        "detect_prompt_injection",
        "prevent_data_exfiltration",
        "restrict_tool_usage"
    ],
    nhi: {
        spendCeiling: 100, // max operations
        rateLimit: 10
    }
};

const aegisMiddleware = async (input: string): Promise<string> => {
    console.log(`[Aegis] Inspecting input for threats: ${input.substring(0, 50)}...`);
    const threats = await detectThreats(input, aegisConfig);
    if (threats.length > 0) {
        console.warn(`[Aegis] Threats detected: ${threats.join(", ")}`);
        return "[BLOCKED BY AEGIS: Threat Detected]";
    }
    return input;
};

// --- LangGraph State ---
interface AgentState {
    messages: BaseMessage[];
    status: string;
}

// --- Agent Nodes ---
const supervisorNode = async (state: AgentState) => {
    const model = new ChatOpenAI({ modelName: "gpt-4-turbo" });
    const lastMessage = state.messages[state.messages.length - 1];
    
    // Protect output using Aegis
    const response = await model.invoke(state.messages);
    const protectedOutput = await protect(response.content.toString(), aegisConfig);
    
    return { 
        messages: [new AIMessage({ content: protectedOutput })],
        status: "routing"
    };
};

const workerNode = async (state: AgentState) => {
    const model = new ChatOpenAI({ modelName: "gpt-3.5-turbo" });
    const response = await model.invoke(state.messages);
    
    // Inspect worker output
    const safeContent = await aegisMiddleware(response.content.toString());
    
    return {
        messages: [new AIMessage({ content: safeContent })],
        status: "completed"
    };
};

// --- Graph Construction ---
const graphBuilder = new StateGraph<AgentState>({
    channels: {
        messages: {
            value: (x: BaseMessage[], y: BaseMessage[]) => x.concat(y),
            default: () => []
        },
        status: {
            value: (x: string, y: string) => y ?? x,
            default: () => "init"
        }
    }
});

graphBuilder.addNode("supervisor", supervisorNode);
graphBuilder.addNode("worker", workerNode);

graphBuilder.addEdge(START, "supervisor");
graphBuilder.addConditionalEdges("supervisor", (state: AgentState) => {
    if (state.messages.length > 5) return END; // Failsafe
    return "worker";
});
graphBuilder.addEdge("worker", END);

// --- Execution ---
async function run() {
    const memory = new MemorySaver();
    const graph = graphBuilder.compile({ checkpointer: memory });
    const config = { configurable: { thread_id: "thread-1" } };

    const userInput = "Calculate the financial risk for the latest merger.";
    console.log(`User: ${userInput}`);
    
    // Input filtering via Aegis
    const safeInput = await aegisMiddleware(userInput);
    if (safeInput.includes("BLOCKED")) {
         console.error("Execution halted by Aegis.");
         return;
    }

    const stream = await graph.stream(
        { messages: [new HumanMessage({ content: safeInput })] },
        config
    );

    for await (const chunk of stream) {
        console.log("Chunk:", chunk);
    }
    
    console.log("Workflow completed successfully.");
}

if (require.main === module) {
    run().catch(console.error);
}
