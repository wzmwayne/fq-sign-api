package com.anjia.unidbgserver.unidbg;

import com.anjia.unidbgserver.utils.TempFileUtils;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import com.github.unidbg.linux.file.SimpleFileIO;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.spi.SyscallHandler;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.github.unidbg.virtualmodule.android.JniGraphics;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IdleFQ extends AbstractJni implements IOResolver<AndroidFileIO> {
    static final java.util.List<String> __ev = java.util.Collections.synchronizedList(new java.util.ArrayList<String>());
    static final long[] __cnt = new long[16];


    private static final Logger log = LoggerFactory.getLogger(IdleFQ.class);

    private static final String BASE_PATH = "com/dragon/read/oversea/gp";
    private static final String APK_PATH = BASE_PATH + "/apk/番茄小说_6.8.1.32.apk";
    private static final String SO_METASEC_ML_PATH = BASE_PATH + "/lib/libmetasec_ml.so";
    private static final String SO_C_SHARE_PATH = BASE_PATH + "/lib/libc++_shared.so";
    private static final String ROOTFS_PATH = BASE_PATH + "/rootfs";
    private static final String MS_CERT_FILE_PATH = BASE_PATH + "/other/ms_16777218.bin";

    private static final String PACKAGE_NAME = "com.dragon.read.oversea.gp";
    private static final String APK_INSTALL_PATH = "/data/app/com.dragon.read.oversea.gp-q5NyjSN9BLSTVBJ54kg7YA==/base.apk";
    private static final int SDK_VERSION = 23;

    private final AndroidEmulator emulator;
    private final VM vm;
    private final Module module;
    private final Memory memory;
    private final DvmClass m;
    private final boolean loggable;

    private File tempApkFile;
    private File tempSoMetasecMlFile;
    private File tempSoCShareFile;
    private File tempRootfsDir;
    private File tempMsCertFile;

    public IdleFQ(boolean loggable) {
        this.loggable = loggable;
        try {
            System.out.println("  [IdleFQ] 1/9 提取临时文件...");
            initTempFiles();
            System.out.println("  [IdleFQ] 2/9 创建模拟器...");
            emulator = AndroidEmulatorBuilder
                .for64Bit()
                .setRootDir(tempRootfsDir)
                .setProcessName(PACKAGE_NAME)
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
            System.out.println("  [IdleFQ] 3/9 初始化模拟器设置...");
            initEmulatorSettings();
            SyscallHandler<AndroidFileIO> handler = emulator.getSyscallHandler();
            handler.setVerbose(false);
            handler.addIOResolver(this);
            memory = emulator.getMemory();
            memory.setLibraryResolver(new AndroidResolver(SDK_VERSION));
            System.out.println("  [IdleFQ] 4/9 创建 DalvikVM...");
            vm = emulator.createDalvikVM();
            vm.setJni(this);
            vm.setVerbose(loggable);
            System.out.println("  [IdleFQ] 5/9 注册 AndroidModule...");
            new AndroidModule(emulator, vm).register(memory);
            System.out.println("  [IdleFQ] 6/9 注册 JniGraphics...");
            new JniGraphics(emulator, vm).register(memory);
            System.out.println("  [IdleFQ] 7/9 加载 libc++_shared.so...");
            vm.loadLibrary(tempSoCShareFile, false);
            System.out.println("  [IdleFQ] 8/9 解析类并加载 libmetasec_ml.so...");
            m = vm.resolveClass("ms/bd/c/m");
            DvmClass a4a = vm.resolveClass("ms/bd/c/a4$a", m);
            DvmClass ms = vm.resolveClass("com/bytedance/mobsec/metasec/ml/MS", a4a);
            DalvikModule dm = vm.loadLibrary(tempSoMetasecMlFile, true);
            module = dm.getModule();
            System.out.println("  [IdleFQ] 9/9 调用 JNI_OnLoad...");
            long t0 = System.currentTimeMillis();
            dm.callJNI_OnLoad(emulator);
            long t1 = System.currentTimeMillis();
            System.out.println("  [IdleFQ] JNI_OnLoad 完成 (" + (t1 - t0) + "ms)");
            log.info("IdleFQ初始化完成");
        } catch (Exception e) {
            log.error("IdleFQ初始化失败", e);
            throw new RuntimeException("IdleFQ初始化失败", e);
        }
    }

    private void initTempFiles() throws IOException {
        try {
            tempApkFile = TempFileUtils.getTempFile(APK_PATH);
            tempSoMetasecMlFile = TempFileUtils.getTempFile(SO_METASEC_ML_PATH);
            tempSoCShareFile = TempFileUtils.getTempFile(SO_C_SHARE_PATH);
            tempMsCertFile = TempFileUtils.getTempFile(MS_CERT_FILE_PATH);
            tempRootfsDir = createTempDir("fq_rootfs");
            if (loggable) {
                log.debug("临时APK文件: {}", tempApkFile.getAbsolutePath());
                log.debug("临时SO主文件: {}", tempSoMetasecMlFile.getAbsolutePath());
                log.debug("临时SO共享库文件: {}", tempSoCShareFile.getAbsolutePath());
                log.debug("临时证书文件: {}", tempMsCertFile.getAbsolutePath());
                log.debug("临时rootfs目录: {}", tempRootfsDir.getAbsolutePath());
            }
        } catch (Exception e) {
            log.error("初始化临时文件失败", e);
            throw new IOException("初始化临时文件失败", e);
        }
    }

    private File createTempDir(String prefix) throws IOException {
        File tempDir = File.createTempFile(prefix, "");
        tempDir.delete();
        if (!tempDir.mkdirs()) {
            throw new IOException("无法创建临时目录: " + tempDir);
        }
        tempDir.deleteOnExit();
        return tempDir;
    }

    private void initEmulatorSettings() {
        Map<String, Integer> iNode = new org.apache.commons.collections4.map.LinkedMap<>();
        iNode.put("/data/system", 671745);
        iNode.put("/data/app", 327681);
        iNode.put("/sdcard/android", 294915);
        iNode.put("/data/user/0/com.dragon.read.oversea.gp", 655781);
        iNode.put("/data/user/0/com.dragon.read.oversea.gp/files", 655864);
        emulator.set("inode", iNode);
        emulator.set("uid", 10074);
    }

    public String generateSignature(String url, String header) {
        try {
            if (loggable) {
                log.debug("准备生成签名 - URL: {}", url);
                log.debug("准备生成签名 - Header: {}", header);
            }
            {
                final long[] HS = new long[]{0x1d1ea0L, 0x1d1ea8L, 0x1d1e78L, 0x1d1ea4L, 0x1d1ddcL, 0x1d1e24L};
                for (int si = 0; si < HS.length; si++) {
                    final int idx = si;
                    emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                        public void onAttach(com.github.unidbg.arm.backend.UnHook uh) {}
                        @Override public void detach() {}
                        @Override public void hook(com.github.unidbg.arm.backend.Backend bk, long address, int size, Object user) {
                            long my; synchronized (__cnt) { __cnt[idx]++; my = __cnt[idx]; }
                            if (my > 40) return;
                            try {
                                com.github.unidbg.arm.context.Arm64RegisterContext cx = (com.github.unidbg.arm.context.Arm64RegisterContext) emulator.getContext();
                                StringBuilder sb = new StringBuilder("Z 0x" + Long.toHexString(HS[idx]) + " #" + my + " lr=0x" + Long.toHexString(cx.getLR() - module.base));
                                for (int r2 = 0; r2 < 4; r2++) {
                                    long pv = cx.getLongArg(r2);
                                    sb.append(" a").append(r2).append("=0x").append(Long.toHexString(pv));
                                    if (pv > 0x1000L && pv < 0x8000000000L) { try { byte[] b = bk.mem_read(pv, 32); sb.append("/");
                                        for (byte z : b) sb.append(String.format("%02x", z & 0xff)); } catch (Throwable ig) {} }
                                }
                                __ev.add(sb.toString());
                            } catch (Throwable ig) { __ev.add("Z-ERR " + ig); }
                        }
                    }, module.base + HS[si], module.base + HS[si] + 4, null);
                }
                Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                    System.out.println("[Z-BEGIN] n=" + __ev.size());
                    for (String e2 : __ev) System.out.println(e2.length() > 300 ? e2.substring(0,300) : e2);
                }));
            }
            Number number = module.callFunction(emulator, 0x168c80, url, header);
            if (number == null) {
                log.error("调用native方法失败，返回结果为null");
                return null;
            }
            UnidbgPointer result = memory.pointer(number.longValue());
            if (result == null) {
                log.error("获取结果指针失败");
                return null;
            }
            String signature = result.getString(0);
            if (loggable) {
                log.debug("签名生成成功: {}", signature);
            }
            return signature;
        } catch (Exception e) {
            log.error("生成签名过程出错: {}", e.getMessage(), e);
            return null;
        }
    }

    public String generateSignature(String url, Map<String, String> headerMap) {
        if (headerMap == null || headerMap.isEmpty()) {
            return generateSignature(url, "");
        }
        StringBuilder headerBuilder = new StringBuilder();
        for (Map.Entry<String, String> entry : headerMap.entrySet()) {
            headerBuilder.append(entry.getKey()).append("\r\n")
                .append(entry.getValue()).append("\r\n");
        }
        String header = headerBuilder.toString();
        if (header.endsWith("\r\n")) {
            header = header.substring(0, header.length() - 2);
        }
        return generateSignature(url, header);
    }

    public String generateSignature(String url) {
        return generateSignature(url, "");
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            case "com/bytedance/mobsec/metasec/ml/MS->b(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;": {
                int i = vaList.getIntArg(0);
                return handleMSMethod(vm, i);
            }
            case "java/lang/Thread->currentThread()Ljava/lang/Thread;":
                return vm.resolveClass("java/lang/Thread").newObject(Thread.currentThread());
        }
        return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
    }

    private DvmObject<?> handleMSMethod(BaseVM vm, int methodId) {
        switch (methodId) {
            case 65539:
                return new StringObject(vm, "/data/user/0/com/dragon/read/oversea/gp/files/.msdata");
            case 33554433:
            case 33554434:
                return DvmBoolean.valueOf(vm, true);
            case 16777232:
                return vm.resolveClass("java.lang.Integer").newObject(68132);
            case 16777233:
                return new StringObject(vm, "6.8.1.32");
            case 16777218: {
                try {
                    if (tempMsCertFile != null && tempMsCertFile.exists()) {
                        byte[] fileData = Files.readAllBytes(tempMsCertFile.toPath());
                        if (loggable) {
                            log.debug("成功读取证书文件: {} bytes", fileData.length);
                        }
                        return new ByteArray(vm, fileData);
                    } else {
                        log.warn("证书文件不存在: {}", tempMsCertFile);
                        return null;
                    }
                } catch (IOException e) {
                    log.error("读取证书文件失败", e);
                    return null;
                }
            }
            case 268435470:
                return vm.resolveClass("java/lang/Long").newObject(System.currentTimeMillis());
            default:
                if (loggable) {
                    log.debug("未处理的MS方法ID: {}", methodId);
                }
                return null;
        }
    }

    @Override
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "java/lang/Thread->getStackTrace()[Ljava/lang/StackTraceElement;": {
                StackTraceElement[] elements = Thread.currentThread().getStackTrace();
                DvmObject[] objs = new DvmObject[elements.length];
                for (int i = 0; i < elements.length; i++) {
                    objs[i] = vm.resolveClass("java/lang/StackTraceElement").newObject(elements[i]);
                }
                return new ArrayObject(objs);
            }
            case "java/lang/StackTraceElement->getClassName()Ljava/lang/String;": {
                StackTraceElement element = (StackTraceElement) dvmObject.getValue();
                return new StringObject(vm, element.getClassName());
            }
            case "java/lang/StackTraceElement->getMethodName()Ljava/lang/String;": {
                StackTraceElement element = (StackTraceElement) dvmObject.getValue();
                return new StringObject(vm, element.getMethodName());
            }
            case "java/lang/Thread->getBytes(Ljava/lang/String;)[B": {
                String arg0 = (String) vaList.getObjectArg(0).getValue();
                if (loggable) {
                    log.debug("java/lang/Thread->getBytes arg0: {}", arg0);
                }
                return new ByteArray(vm, arg0.getBytes(StandardCharsets.UTF_8));
            }
            case "java/lang/Long->longValue()J": {
                Object value = dvmObject.getValue();
                if (value instanceof Long) {
                    return (DvmObject<Long>) value;
                }
            }
        }
        return super.callObjectMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public long callLongMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if ("java/lang/Long->longValue()J".equals(signature)) {
            Object value = dvmObject.getValue();
            if (value instanceof Long) {
                return (Long) value;
            }
        }
        return super.callLongMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        if (loggable) {
            log.debug("getStaticIntField: {}", signature);
        }
        if ("com/bytedance/mobsec/metasec/ml/MS->a()V".equals(signature)) {
            return 0x40;
        }
        throw new UnsupportedOperationException(signature);
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        if (loggable) {
            log.debug("callVoidMethod: {}", signature);
        }
        switch (signature) {
            case "com/bytedance/mobsec/metasec/ml/MS->a()V":
                if (loggable) {
                    log.debug("Patched: com/bytedance/mobsec/metasec/ml/MS->a()V");
                }
                return;
        }
        super.callVoidMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if ("java/lang/Integer->intValue()I".equals(signature)) {
            Object value = dvmObject.getValue();
            if (value instanceof Integer) {
                return (Integer) value;
            }
            if (value instanceof String) {
                return Integer.parseInt((String) value);
            }
        }
        return super.callIntMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if ("java/lang/Boolean->booleanValue()Z".equals(signature)) {
            Object value = dvmObject.getValue();
            if (value instanceof Boolean) {
                return (Boolean) value;
            }
            if (value instanceof String) {
                return Boolean.parseBoolean((String) value);
            }
        }
        return super.callBooleanMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public FileResult resolve(Emulator emulator, String pathname, int oflags) {
        if (loggable) {
            log.debug("resolve ==> {}", pathname);
        }
        if (pathname.contains("libmetasec_ml.so")) {
            return FileResult.success(new SimpleFileIO(oflags, tempSoMetasecMlFile, pathname));
        }
        if (pathname.equals(APK_INSTALL_PATH)) {
            return FileResult.success(new SimpleFileIO(oflags, tempApkFile, pathname));
        }
        return null;
    }

    public void destroy() {
        if (emulator != null) {
            try {
                emulator.close();
                log.info("IdleFQ资源已释放");
            } catch (Exception e) {
                log.error("关闭模拟器失败", e);
            }
        }
    }
}
