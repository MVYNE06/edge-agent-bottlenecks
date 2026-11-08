import os
import time
from laya.agent import Agent

print("=" * 70)
print("EMPIRICAL BENCHMARK: Laya-421M (ModernBERT) System-1 Decision Model")
print("Platform: AMD Ryzen 5 5625U (Zen 3 CPU, 6C/12T) | Execution: FP32")
print("=" * 70)

# Use local cache snapshot if available, otherwise fallback to Hugging Face model hub
default_local = "C:/Users/aaron/.cache/huggingface/hub/models--convaiinnovations--laya/snapshots/7b928d828b7b0e022f929d9bd2e44165aa270148"
model_dir = os.environ.get("LAYA_MODEL_PATH", default_local if os.path.exists(default_local) else "convaiinnovations/laya")

print(f"\n[1/3] Loading Laya-421M Weights into Memory...")
t0 = time.perf_counter()
agent = Agent(model_dir, device="cpu")
load_dur = (time.perf_counter() - t0) * 1000
print(f"      Model loaded in {load_dur:.1f} ms\n")

state = "User request: Use obscura_browse to fetch https://news.ycombinator.com and summarize the top headline."
questions = {
    "tool_route": {
        "type": "choice",
        "instructions": "Which tool should be executed to handle the user's request?",
        "criteria": [
            "local_file_io",
            "obscura_web_fetch",
            "delegate_complex_coding_to_cloud",
            "direct_chat_reply"
        ]
    }
}

print("[2/3] Performing Warm-Up Forward Pass...")
_ = agent.predict(state, questions)
print("      Warm-up forward pass complete!\n")

print("[3/3] Running 5-Pass Latency Benchmark...")
latencies = []
result = None
for i in range(5):
    t_start = time.perf_counter()
    result = agent.predict(state, questions)
    dur_ms = (time.perf_counter() - t_start) * 1000
    latencies.append(dur_ms)
    print(f"      Iteration {i+1}: {dur_ms:.2f} ms")

avg_latency = sum(latencies) / len(latencies)
ans = result["answers"]
route_ans = ans["tool_route"]

print("\n" + "=" * 70)
print("BENCHMARK VERIFICATION RESULTS:")
print(f"  Task State:               \"{state}\"")
print(f"  Predicted Route:          {route_ans['choice']} (Confidence: {route_ans['confidence']:.2%})")
print(f"  Routing Probabilities:    {route_ans['probabilities']}")
print(f"  Single-Pass Latency:      {avg_latency:.2f} ms")
print(f"  Tokens Generated:         0 (Non-Autoregressive Matrix Pass)")
print(f"  Input Tokens Processed:   {result['usage']['input_tokens']}")
print("=" * 70)
