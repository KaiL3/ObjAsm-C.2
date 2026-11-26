using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

// Bidirectional TLS echo client: writes and reads at the same time on separate threads.
public class EchoClient {
  public long Sent, Received;
  public string Error = "";
  public volatile bool ReadDone;
  long total; string host; int port;
  TcpClient c; SslStream s;

  public EchoClient(string host, int port, long totalBytes) { this.host = host; this.port = port; total = totalBytes; }

  public void Start() {
    c = new TcpClient(host, port);
    c.ReceiveTimeout = 10000; c.SendTimeout = 10000;          // handshake must not hang
    s = new SslStream(c.GetStream(), false, (a, b, d, e) => true);
    s.AuthenticateAsClient("localhost");
    c.ReceiveTimeout = 0; c.SendTimeout = 0;                  // data phase: stalls are measured
    new Thread(ReadLoop) { IsBackground = true }.Start();
    new Thread(WriteLoop) { IsBackground = true }.Start();
  }

  void WriteLoop() {
    try {
      byte[] buf = new byte[16384];
      for (int i = 0; i < buf.Length; i++) buf[i] = (byte)(65 + i % 26);
      buf[buf.Length - 1] = 0;                                 // one message per buffer
      while (Interlocked.Read(ref Sent) < total) {
        s.Write(buf, 0, buf.Length);
        Interlocked.Add(ref Sent, buf.Length);
      }
    } catch (Exception e) { Error += "W: " + e.Message + " "; }
  }

  public int ReadChunk = 65536, ReadDelayMs = 0;             // slow reader simulation

  void ReadLoop() {
    try {
      byte[] buf = new byte[ReadChunk]; int n;
      while ((n = s.Read(buf, 0, buf.Length)) > 0) {
        if (Interlocked.Add(ref Received, n) >= total) break;
        if (ReadDelayMs > 0) Thread.Sleep(ReadDelayMs);
      }
    } catch (Exception e) { Error += "R: " + e.Message + " "; }
    ReadDone = true;
  }

  public void Close() { try { c.Close(); } catch { } }
}

public static class Idle {
  // TLS handshake through the proxy, then idle: seconds until the other side closes (or maxMs).
  public static double SecondsUntilClosed(string host, int port, int maxMs) {
    TcpClient c = new TcpClient(host, port);
    c.ReceiveTimeout = 10000;
    SslStream s = new SslStream(c.GetStream(), false, (a, b, d, e) => true);
    s.AuthenticateAsClient("localhost");
    c.ReceiveTimeout = maxMs;
    System.Diagnostics.Stopwatch sw = System.Diagnostics.Stopwatch.StartNew();
    try { byte[] buf = new byte[256]; s.Read(buf, 0, buf.Length); } catch { }
    double t = sw.Elapsed.TotalSeconds;
    c.Close();
    return t;
  }
}

public static class Win {
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr hDlg, int id);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr SendMessage(IntPtr h, uint msg, IntPtr w, string l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
}

// Wait Chain Traversal: reports deadlock cycles (critical sections, mutexes, ...)
public static class Wct {
  [StructLayout(LayoutKind.Explicit, Size = 280)]
  public struct NODE {
    [FieldOffset(0)] public int ObjectType;      // 1 = CriticalSection, 8 = Thread
    [FieldOffset(4)] public int ObjectStatus;
    [FieldOffset(8)] public int ProcessId;       // ThreadObject
    [FieldOffset(12)] public int ThreadId;
    [FieldOffset(16)] public int WaitTime;
    [FieldOffset(20)] public int ContextSwitches;
  }
  [DllImport("advapi32.dll", SetLastError = true)] static extern IntPtr OpenThreadWaitChainSession(int flags, IntPtr cb);
  [DllImport("advapi32.dll")] static extern void CloseThreadWaitChainSession(IntPtr h);
  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool GetThreadWaitChain(IntPtr h, IntPtr ctx, int flags, int threadId, ref int count, [Out] NODE[] nodes, out bool isCycle);

  static string TypeName(int t) {
    switch (t) { case 1: return "CritSect"; case 2: return "SendMessage"; case 3: return "Mutex"; case 8: return "Thread"; default: return "Type" + t; }
  }

  public static string Analyze(int[] threadIds) {
    StringBuilder sb = new StringBuilder();
    IntPtr h = OpenThreadWaitChainSession(0, IntPtr.Zero);
    if (h == IntPtr.Zero) return "OpenThreadWaitChainSession failed: " + Marshal.GetLastWin32Error();
    int cycles = 0, blocked = 0;
    foreach (int tid in threadIds) {
      NODE[] nodes = new NODE[16]; int count = 16; bool cycle;
      if (!GetThreadWaitChain(h, IntPtr.Zero, 1, tid, ref count, nodes, out cycle)) {
        sb.AppendLine("  thread " + tid + ": GetThreadWaitChain error " + Marshal.GetLastWin32Error());
        continue;
      }
      bool waitsOnLock = false;
      for (int i = 0; i < count; i++) if (nodes[i].ObjectType == 1) waitsOnLock = true;
      if (!cycle && !waitsOnLock) continue;
      if (cycle) cycles++; else blocked++;
      sb.Append("  thread " + tid + (cycle ? " CYCLE: " : " waits: "));
      for (int i = 0; i < count; i++) {
        if (i > 0) sb.Append(" -> ");
        sb.Append(TypeName(nodes[i].ObjectType));
        if (nodes[i].ObjectType == 8) sb.Append("(" + nodes[i].ThreadId + ")");
      }
      sb.AppendLine();
    }
    CloseThreadWaitChainSession(h);
    sb.Insert(0, "Wait chains: " + cycles + " thread(s) in a cycle, " + blocked + " other(s) waiting on a critical section\n");
    return sb.ToString();
  }
}
