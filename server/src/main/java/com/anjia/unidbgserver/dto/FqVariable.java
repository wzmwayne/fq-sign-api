package com.anjia.unidbgserver.dto;

public class FqVariable {

    private String installId;
    private String serverDeviceId;
    private String aid;
    private String updateVersionCode;
    private String keyRegisterTs;
    private String deviceId;
    private String ac;
    private String channel;
    private String appName;
    private String versionCode;
    private String versionName;
    private String devicePlatform;
    private String os;
    private String ssmix;
    private String deviceType;
    private String deviceBrand;
    private String language;
    private String osApi;
    private String osVersion;
    private String manifestVersionCode;
    private String resolution;
    private String dpi;
    private String rticket;
    private String hostAbi;
    private String dragonDeviceType;
    private String pvPlayer;
    private String complianceStatus;
    private String needPersonalRecommend;
    private String playerSoLoad;
    private String isAndroidPadScreen;
    private String romVersion;
    private String cdid;

    public FqVariable() {
        initializeDefaults();
    }

    public FqVariable(String installId, String serverDeviceId, String aid, String updateVersionCode) {
        this.installId = installId;
        this.serverDeviceId = serverDeviceId;
        this.aid = aid;
        this.updateVersionCode = updateVersionCode;
        initializeDefaults();
    }

    public void setFromDeviceParams(String deviceId, String installId, String cdid) {
        this.deviceId = deviceId;
        this.serverDeviceId = deviceId;
        this.installId = installId;
        this.cdid = cdid;
    }

    private void initializeDefaults() {
        this.installId = "933935730456617";
        this.serverDeviceId = "933935730452521";
        this.aid = "1967";
        this.updateVersionCode = "68132";
        this.keyRegisterTs = "0";
        this.deviceId = this.serverDeviceId;
        this.ac = "wifi";
        this.channel = "googleplay";
        this.appName = "novelapp";
        this.versionCode = "68132";
        this.versionName = "6.8.1.32";
        this.devicePlatform = "android";
        this.os = "android";
        this.ssmix = "a";
        this.deviceType = "OnePlus11";
        this.deviceBrand = "OnePlus";
        this.language = "zh";
        this.osApi = "32";
        this.osVersion = "12";
        this.manifestVersionCode = "68132";
        this.resolution = "3200*1440";
        this.dpi = "640";
        this.rticket = String.valueOf(System.currentTimeMillis());
        this.hostAbi = "arm64-v8a";
        this.dragonDeviceType = "phone";
        this.pvPlayer = "68132";
        this.complianceStatus = "0";
        this.needPersonalRecommend = "1";
        this.playerSoLoad = "1";
        this.isAndroidPadScreen = "0";
        this.romVersion = "V291IR+release-keys";
        this.cdid = "17f05006-423a-4172-be4b-7d26a42f2f4a";
    }

    public String getInstallId() { return installId; }
    public void setInstallId(String installId) { this.installId = installId; }
    public String getServerDeviceId() { return serverDeviceId; }
    public void setServerDeviceId(String serverDeviceId) { this.serverDeviceId = serverDeviceId; }
    public String getAid() { return aid; }
    public void setAid(String aid) { this.aid = aid; }
    public String getUpdateVersionCode() { return updateVersionCode; }
    public void setUpdateVersionCode(String updateVersionCode) { this.updateVersionCode = updateVersionCode; }
    public String getKeyRegisterTs() { return keyRegisterTs; }
    public void setKeyRegisterTs(String keyRegisterTs) { this.keyRegisterTs = keyRegisterTs; }
    public String getDeviceId() { return deviceId; }
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }
    public String getAc() { return ac; }
    public void setAc(String ac) { this.ac = ac; }
    public String getChannel() { return channel; }
    public void setChannel(String channel) { this.channel = channel; }
    public String getAppName() { return appName; }
    public void setAppName(String appName) { this.appName = appName; }
    public String getVersionCode() { return versionCode; }
    public void setVersionCode(String versionCode) { this.versionCode = versionCode; }
    public String getVersionName() { return versionName; }
    public void setVersionName(String versionName) { this.versionName = versionName; }
    public String getDevicePlatform() { return devicePlatform; }
    public void setDevicePlatform(String devicePlatform) { this.devicePlatform = devicePlatform; }
    public String getOs() { return os; }
    public void setOs(String os) { this.os = os; }
    public String getSsmix() { return ssmix; }
    public void setSsmix(String ssmix) { this.ssmix = ssmix; }
    public String getDeviceType() { return deviceType; }
    public void setDeviceType(String deviceType) { this.deviceType = deviceType; }
    public String getDeviceBrand() { return deviceBrand; }
    public void setDeviceBrand(String deviceBrand) { this.deviceBrand = deviceBrand; }
    public String getLanguage() { return language; }
    public void setLanguage(String language) { this.language = language; }
    public String getOsApi() { return osApi; }
    public void setOsApi(String osApi) { this.osApi = osApi; }
    public String getOsVersion() { return osVersion; }
    public void setOsVersion(String osVersion) { this.osVersion = osVersion; }
    public String getManifestVersionCode() { return manifestVersionCode; }
    public void setManifestVersionCode(String manifestVersionCode) { this.manifestVersionCode = manifestVersionCode; }
    public String getResolution() { return resolution; }
    public void setResolution(String resolution) { this.resolution = resolution; }
    public String getDpi() { return dpi; }
    public void setDpi(String dpi) { this.dpi = dpi; }
    public String getRticket() { return rticket; }
    public void setRticket(String rticket) { this.rticket = rticket; }
    public String getHostAbi() { return hostAbi; }
    public void setHostAbi(String hostAbi) { this.hostAbi = hostAbi; }
    public String getDragonDeviceType() { return dragonDeviceType; }
    public void setDragonDeviceType(String dragonDeviceType) { this.dragonDeviceType = dragonDeviceType; }
    public String getPvPlayer() { return pvPlayer; }
    public void setPvPlayer(String pvPlayer) { this.pvPlayer = pvPlayer; }
    public String getComplianceStatus() { return complianceStatus; }
    public void setComplianceStatus(String complianceStatus) { this.complianceStatus = complianceStatus; }
    public String getNeedPersonalRecommend() { return needPersonalRecommend; }
    public void setNeedPersonalRecommend(String needPersonalRecommend) { this.needPersonalRecommend = needPersonalRecommend; }
    public String getPlayerSoLoad() { return playerSoLoad; }
    public void setPlayerSoLoad(String playerSoLoad) { this.playerSoLoad = playerSoLoad; }
    public String getIsAndroidPadScreen() { return isAndroidPadScreen; }
    public void setIsAndroidPadScreen(String isAndroidPadScreen) { this.isAndroidPadScreen = isAndroidPadScreen; }
    public String getRomVersion() { return romVersion; }
    public void setRomVersion(String romVersion) { this.romVersion = romVersion; }
    public String getCdid() { return cdid; }
    public void setCdid(String cdid) { this.cdid = cdid; }
}
