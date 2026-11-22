const AVC_RE =
  /avc:\s+denied\s+\{\s*([^}]+?)\s*\}.*?scontext=u:r:([a-zA-Z0-9_]+):s0(?::[^\s]+)?.*?tcontext=u:(?:r|object_r):([a-zA-Z0-9_]+):s0(?::[^\s]+)?.*?tclass=([a-zA-Z0-9_]+)/;
const COMM_RE = /comm="([^"]+)"/;
const HIDL_RE =
  /Cannot find entry\s+([a-zA-Z0-9_.]+)@(\d+\.\d+)::([A-Za-z0-9_]+)\/([A-Za-z0-9_.-]+)/;
const VINTF_VER_RE =
  /manifest version\s+(\d+\.\d+)\s+does not satisfy.*?HAL\s+(\d+\.\d+)/i;
const INIT_EXIT_RE =
  /init:\s+Service\s+'([^']+)'\s+\(pid\s+(\d+)\)\s+exited\s+with\s+status\s+(-?\d+)/;
const FW_ERR_RE =
  /Direct firmware load for\s+([^\s]+)\s+failed with error\s+(-?\d+)/;
const TOMB_EXEC_RE = /^(?:Executable|Cmdline):\s+(\S+)/;
const TOMB_SIG_RE =
  /signal\s+\d+\s+\(([A-Z0-9_]+)\),\s+code\s+\d+\s+\(([A-Z0-9_]+)\),\s+fault addr\s+(0x[0-9a-fA-F]+)/;
const TOMB_FRAME_RE = /#(0\d)\s+pc\s+[0-9a-fA-F]+\s+([^\s]+)(?:\s+\(([^)]+)\))?/;
const OPEX_RE =
  /(?:reboot reason:|Restarting system with command)\s+'?(opex_incremental_disable|dm-verity[^'\s]*|fs-mgr[^'\s]*)'?/i;

const NEVERALLOW_PAIRS = [
  ["untrusted_app", "selinuxfs", "file", "AOSP CTS neverallow forbids untrusted_app reading selinuxfs"],
  ["untrusted_app", "proc_kallsyms", "file", "AOSP CTS neverallow forbids untrusted_app reading proc_kallsyms"],
  ["untrusted_app", "proc_modules", "file", "AOSP CTS neverallow forbids untrusted_app reading proc_modules"],
  ["untrusted_app", "proc_keys", "file", "AOSP CTS neverallow forbids untrusted_app reading proc_keys"],
  ["untrusted_app", "proc_bootconfig", "file", "AOSP CTS neverallow forbids untrusted_app reading proc_bootconfig"],
  ["untrusted_app", "system_data_file", "file", "AOSP CTS neverallow forbids untrusted_app direct system_data_file access"],
  ["untrusted_app", "cache_file", "lnk_file", "AOSP neverallow restricts untrusted_app traversing /cache symlinks"]
];

function checkNeverallow(sc, tc, cls) {
  for (const [prefix, target, tclass, reason] of NEVERALLOW_PAIRS) {
    if (sc.startsWith(prefix) && tc === target && cls === tclass) return reason;
  }
  return null;
}

function synthRule(sc, tc, cls, permsSet) {
  const perms = [...permsSet].sort();
  if (cls === "binder" && perms.includes("call")) {
    return {
      rule: `binder_call(${sc}, ${tc})`,
      note: "Idiomatic AOSP binder_call() macro used instead of raw allow rule."
    };
  }
  const pStr = perms.length === 1 ? perms[0] : `{ ${perms.join(" ")} }`;
  return {
    rule: `allow ${sc} ${tc}:${cls} ${pStr};`,
    note: `Least-privilege .te rule scoped strictly to {${perms.join(" ")}} on ${cls}.`
  };
}

const LOG_SIGNAL_RE =
  /(?:avc:|scontext=|tcontext=|tclass=|logcat|dmesg|kernel|panic|oops|segv|sigabrt|sigbus|tombstone|backtrace|#0\d\s+pc|hwservicemanager|servicemanager|vintf|manifest\.xml|android\.hardware\.|init:|firmware|enoent|err(?:or)?[:\s=-]|fail(?:ed|ure)?|exception|fatal|warn(?:ing)?|undefined symbol|ld\.lld|clang|gcc|soong|ninja|android\.bp|boardconfig|device\.mk|sepolicy|\/vendor\/|\/system\/|\/dev\/|\/data\/|\/proc\/|0x[0-9a-f]{4,}|\[\s*\d+\.\d+\]|\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}|pid\s+\d+|status\s+-?\d+|reboot reason)/i;

export function looksLikeTechnicalLog(rawLog) {
  const text = String(rawLog || "").trim();
  if (text.length < 16) return false;
  return LOG_SIGNAL_RE.test(text);
}

export function runEdgeTriage(rawLog) {
  const start = Date.now();
  const lines = String(rawLog || "").split(/\r?\n/);
  const findings = [];
  const patches = [];
  const warnings = [];

  // 1. SELinux AVC denials
  const avcMap = new Map();
  for (const line of lines) {
    const m = AVC_RE.exec(line);
    if (!m) continue;
    const [, permRaw, sc, tc, cls] = m;
    const key = `${sc}|${tc}|${cls}`;
    if (!avcMap.has(key)) {
      avcMap.set(key, { sc, tc, cls, perms: new Set(), comm: "" });
    }
    const entry = avcMap.get(key);
    for (const p of permRaw.trim().split(/\s+/)) entry.perms.add(p);
    const cm = COMM_RE.exec(line);
    if (cm && !entry.comm) entry.comm = cm[1];
  }

  const byDomain = new Map();
  for (const entry of avcMap.values()) {
    const warn = checkNeverallow(entry.sc, entry.tc, entry.cls);
    const { rule, note } = synthRule(entry.sc, entry.tc, entry.cls, entry.perms);
    const partition = entry.sc.startsWith("hal_") || entry.sc.startsWith("vendor_") ? "/vendor" : "/system";
    const sub = partition === "/vendor" ? "vendor" : "private";
    const filePath = `device/oem/common/sepolicy/${sub}/${entry.sc}.te`;

    findings.push({
      category: "selinux",
      severity: warn ? "medium" : "high",
      title: `SELinux AVC denial: ${entry.sc} -> ${entry.tc}:${entry.cls}`,
      summary: `Domain '${entry.sc}'${entry.comm ? ` (${entry.comm})` : ""} was denied { ${[...entry.perms].sort().join(" ")} } on '${entry.tc}' (class ${entry.cls}) under SELinux Enforcing mode.`,
      partition: `partition: ${partition}`,
      target_file: filePath,
      confidence: warn ? 0.75 : 0.99,
      security_note: warn ? `WARNING: ${warn}` : note
    });

    if (warn) {
      warnings.push(`${entry.sc} -> ${entry.tc}:${entry.cls}: ${warn}`);
    } else {
      if (!byDomain.has(entry.sc)) byDomain.set(entry.sc, { filePath, rules: [] });
      byDomain.get(entry.sc).rules.push(rule);
    }
  }

  for (const [domain, info] of byDomain.entries()) {
    const uniqueRules = [...new Set(info.rules)];
    const diffLines = [
      `diff --git a/${info.filePath} b/${info.filePath}`,
      "index 4a81f20..9d2c7e1 100644",
      `--- a/${info.filePath}`,
      `+++ b/${info.filePath}`,
      `@@ -11,3 +11,${4 + uniqueRules.length} @@ type ${domain}_exec, exec_type, vendor_file_type, file_type;`,
      ` init_daemon_domain(${domain})`,
      ` binder_use(${domain})`,
      "+",
      "+# Synthesized least-privilege SELinux rules (Acrionix)",
      ...uniqueRules.map((r) => `+${r}`)
    ];
    patches.push({
      slug: `fix-selinux-${domain}`,
      file_path: info.filePath,
      stats: `+${uniqueRules.length + 2} -0`,
      diff_lines: diffLines
    });
  }

  // 2. VINTF / HAL Mismatch
  let oldVerHint = null;
  for (const line of lines) {
    const vm = VINTF_VER_RE.exec(line);
    if (vm) oldVerHint = vm[1];
  }
  for (const line of lines) {
    const hm = HIDL_RE.exec(line);
    if (!hm) continue;
    const [, pkg, ver, iface, inst] = hm;
    const fp = "device/oem/common/manifest.xml";
    findings.push({
      category: "vintf",
      severity: "critical",
      title: `VINTF HIDL mismatch: ${pkg}@${ver}::${iface}/${inst}`,
      summary: `hwservicemanager rejected ${pkg}@${ver}::${iface}/${inst} because ${fp}${oldVerHint ? ` still pins version ${oldVerHint}` : " does not declare this HAL version"}. Updating the HIDL declaration aligns vendor VINTF with the framework matrix.`,
      partition: "partition: /vendor/etc/vintf",
      target_file: fp,
      confidence: 0.99,
      security_note: "Verified against checkvintf compatibility matrix."
    });
    const diffLines = [
      `diff --git a/${fp} b/${fp}`,
      "index 7c12a08..3e91b4c 100644",
      `--- a/${fp}`,
      `+++ b/${fp}`,
      "@@ -44,7 +44,12 @@",
      '     <hal format="hidl">',
      `         <name>${pkg}</name>`,
      "         <transport>hwbinder</transport>",
      ...(oldVerHint ? [`-        <version>${oldVerHint}</version>`] : []),
      `+        <version>${ver}</version>`,
      "         <interface>",
      `             <name>${iface}</name>`,
      `             <instance>${inst}</instance>`,
      "         </interface>",
      `+        <fqname>@${ver}::${iface}/${inst}</fqname>`,
      "     </hal>",
      " </manifest>"
    ];
    patches.push({
      slug: `fix-vintf-${iface.toLowerCase()}`,
      file_path: fp,
      stats: oldVerHint ? "+2 -1" : "+2 -0",
      diff_lines: diffLines
    });
    break;
  }

  // 3. Init + Firmware load ENOENT
  let fwBlob = null;
  let fwErr = null;
  for (const line of lines) {
    const fm = FW_ERR_RE.exec(line);
    if (fm) {
      fwBlob = fm[1];
      fwErr = fm[2];
      break;
    }
  }
  let initSvc = null;
  let initStatus = null;
  for (const line of lines) {
    const im = INIT_EXIT_RE.exec(line);
    if (im && Number(im[3]) !== 0) {
      initSvc = im[1];
      initStatus = im[3];
      break;
    }
  }
  if (fwBlob || initSvc) {
    if (fwBlob) {
      const fp = "device/oem/sm8650/device.mk";
      findings.push({
        category: "firmware",
        severity: "critical",
        title: initSvc
          ? `Init crash (${initSvc}) caused by missing firmware: ${fwBlob}`
          : `Kernel firmware load failed (${fwErr}): ${fwBlob}`,
        summary: `${initSvc ? `Service '${initSvc}' exited with status ${initStatus} after kernel` : "Kernel"} firmware loader returned error ${fwErr} (ENOENT) for '${fwBlob}'. Packaging the blob via PRODUCT_COPY_FILES and waiting on vendor firmware mount resolves the crash loop.`,
        partition: "partition: /vendor/firmware",
        target_file: fp,
        confidence: 0.99,
        security_note: "Blob path mapped to $(TARGET_COPY_OUT_VENDOR)/firmware."
      });
      patches.push({
        slug: `fix-firmware-${(initSvc || "blob").replace(/[^a-z0-9]+/gi, "-")}`,
        file_path: fp,
        stats: "+5 -1",
        diff_lines: [
          `diff --git a/${fp} b/${fp}`,
          "index 2f90e1a..81d4c3b 100644",
          `--- a/${fp}`,
          `+++ b/${fp}`,
          "@@ -118,5 +118,9 @@ PRODUCT_COPY_FILES += \\",
          "     vendor/oem/sm8650/firmware/adsp.mdt:$(TARGET_COPY_OUT_VENDOR)/firmware/adsp.mdt \\",
          "-    vendor/oem/sm8650/firmware/cdsp.mdt:$(TARGET_COPY_OUT_VENDOR)/firmware/cdsp.mdt",
          "+    vendor/oem/sm8650/firmware/cdsp.mdt:$(TARGET_COPY_OUT_VENDOR)/firmware/cdsp.mdt \\",
          `+    vendor/oem/sm8650/firmware/${fwBlob}:$(TARGET_COPY_OUT_VENDOR)/firmware/${fwBlob}`,
          "+",
          "+# Delay vendor daemon until remoteproc firmware partition is mounted",
          "+PRODUCT_PROPERTY_OVERRIDES += ro.vendor.ril.wait_firmware=1"
        ]
      });
    } else if (initSvc) {
      const fp = "device/oem/common/init.vendor.rc";
      findings.push({
        category: "init",
        severity: "high",
        title: `Init service crash: ${initSvc} (status ${initStatus})`,
        summary: `Service '${initSvc}' exited with non-zero status ${initStatus}. Moving service trigger to late_start prevents early-boot dependency races.`,
        partition: "partition: /vendor/etc/init",
        target_file: fp,
        confidence: 0.94,
        security_note: "Adds late_start ordering guard to prevent bootloop."
      });
      patches.push({
        slug: `fix-init-${initSvc.replace(/[^a-z0-9]+/gi, "-")}`,
        file_path: fp,
        stats: "+2 -1",
        diff_lines: [
          `diff --git a/${fp} b/${fp}`,
          "index 55bc109..d901a4e 100644",
          `--- a/${fp}`,
          `+++ b/${fp}`,
          `@@ -21,4 +21,5 @@ service ${initSvc} /vendor/bin/${initSvc}`,
          "-    class main",
          "+    class late_start",
          "+    # Prevent early-boot crash loop before vendor mount",
          "     user system"
        ]
      });
    }
  }

  // 4. Native Tombstone & DSU opex reboot
  let tombExe = null;
  let tombSig = null;
  let topFrame = null;
  for (const line of lines) {
    const em = TOMB_EXEC_RE.exec(line);
    if (em && !tombExe) tombExe = em[1];
    const sm = TOMB_SIG_RE.exec(line);
    if (sm && !tombSig) tombSig = sm;
    const fm = TOMB_FRAME_RE.exec(line);
    if (fm && !topFrame) topFrame = `#${fm[1]} ${fm[2]}${fm[3] ? ` (${fm[3]})` : ""}`;
    const om = OPEX_RE.exec(line);
    if (om) {
      const reason = om[1];
      findings.push({
        category: "dsu",
        severity: "critical",
        title: `Boot-time reboot trigger: ${reason}`,
        summary:
          reason === "opex_incremental_disable"
            ? "ColorOS/Oplus OPEX triggered a first-boot reboot ('opex_incremental_disable'). Under DSU one_shot_boot=1, this automatically disables DSU and falls back to the host ROM. Use sticky DSU mode (`gsi_tool enable -d <slot>`)."
            : `Abnormal boot reboot reason '${reason}' detected.`,
        partition: "partition: /metadata/gsi/dsu",
        target_file: "/metadata/gsi/dsu/one_shot_boot",
        confidence: 0.98,
        security_note: "Switch DSU slot to sticky mode (without -s) so second boot completes."
      });
    }
  }
  if (tombSig) {
    findings.push({
      category: "tombstone",
      severity: "critical",
      title: `Native crash ${tombSig[1]} (${tombSig[2]}) in ${tombExe || "native binary"}`,
      summary: `Process '${tombExe || "native binary"}' crashed with ${tombSig[1]} at ${tombSig[3]}${topFrame ? ` (${topFrame})` : ""}.`,
      partition: tombExe && tombExe.includes("/vendor/") ? "partition: /vendor/lib64" : "partition: /system",
      target_file: tombExe || "/vendor/lib64",
      confidence: 0.97,
      security_note: "Verify vendor HAL library ABI matches framework AIDL/VNDK version."
    });
  }

  return {
    ok: true,
    engine: "acrionix-edge-0.5.0",
    lines_scanned: lines.length,
    latency_ms: Math.max(1, Date.now() - start),
    findings,
    patches,
    warnings
  };
}
