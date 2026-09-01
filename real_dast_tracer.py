import os
import sys
import time
import json
from bcc import BPF

BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>

struct event_data_t {
    u32 pid;
    u64 ts;
    char comm[16];
    char sym[32];
};

BPF_PERF_OUTPUT(events);

static inline void record_event(struct pt_regs *ctx, const char *name) {
    struct event_data_t event = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    event.pid = pid_tgid >> 32;
    event.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(event.sym, name, sizeof(event.sym));
    events.perf_submit(ctx, &event, sizeof(event));
}

int trace_C_Initialize(struct pt_regs *ctx) {
    record_event(ctx, "C_Initialize");
    return 0;
}

int trace_C_OpenSession(struct pt_regs *ctx) {
    record_event(ctx, "C_OpenSession");
    return 0;
}

int trace_C_SignInit(struct pt_regs *ctx) {
    record_event(ctx, "C_SignInit");
    return 0;
}

int trace_C_Sign(struct pt_regs *ctx) {
    record_event(ctx, "C_Sign");
    return 0;
}

int trace_C_SignUpdate(struct pt_regs *ctx) {
    record_event(ctx, "C_SignUpdate");
    return 0;
}

int trace_C_SignFinal(struct pt_regs *ctx) {
    record_event(ctx, "C_SignFinal");
    return 0;
}
"""

def resolve_target_library():
    sudo_user = os.environ.get("SUDO_USER")
    base_dir = f"/home/{sudo_user}" if sudo_user else os.path.expanduser("~")

    candidate_paths = [
        os.path.join(base_dir, "softhsm2_install/lib/softhsm/libsofthsm2.so"),
        "/home/cab21/softhsm2_install/lib/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so"
    ]

    for path in candidate_paths:
        if os.path.exists(path):
            return os.path.realpath(path)

    return None

def main():
    target_lib = resolve_target_library()
    if not target_lib:
        print("[!] Error: Could not locate 'libsofthsm2.so' in standard user paths.")
        sys.exit(1)

    print(f"[*] Attaching kernel uprobes to binary: {target_lib}")
    b = BPF(text=BPF_PROGRAM)

    symbols = [
        "C_Initialize",
        "C_OpenSession",
        "C_SignInit",
        "C_Sign",
        "C_SignUpdate",
        "C_SignFinal"
    ]

    hooked_count = 0
    for sym in symbols:
        try:
            b.attach_uprobe(name=target_lib, sym=sym, fn_name=f"trace_{sym}")
            print(f"  [+] Active probe attached: {sym}")
            hooked_count += 1
        except Exception as e:
            print(f"  [-] Failed to attach {sym}: {e}")

    print(f"\n[+] Total {hooked_count} uprobes active. Listening for PKCS#11 operations...")
    captured_events = []

    def handle_event(cpu, data, size):
        event = b["events"].event(data)
        record = {
            "pid": event.pid,
            "process": event.comm.decode('utf-8', 'replace'),
            "symbol": event.sym.decode('utf-8', 'replace'),
            "timestamp_ns": event.ts,
            "target_binary": target_lib,
            "wall_time": time.time()
        }
        captured_events.append(record)
        print(f"[eBPF TRAP] PID: {event.pid:<7} | Process: {record['process']:<12} | Function: {record['symbol']}")

    b["events"].open_perf_buffer(handle_event)

    try:
        while True:
            b.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        print("\n[*] Draining trace ring buffers...")
        for _ in range(5):
            b.perf_buffer_poll(timeout=50)

    output_file = "production_dast_cbom_evidence.json"
    with open(output_file, "w") as out:
        json.dump(captured_events, out, indent=2)

    print(f"\n[+] Successfully exported {len(captured_events)} runtime telemetry events to {output_file}")

if __name__ == "__main__":
    main()
