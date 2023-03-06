package com.example.unionpay.sdk.gm;

import static com.example.unionpay.sdk.SDKConstants.POINT;
import static com.example.unionpay.sdk.SDKConstants.UNIONPAY_CNNAME;
import static com.example.unionpay.sdk.SDKUtil.isEmpty;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import com.example.unionpay.sdk.CertUtil;


public class GmCertUtil{


	static class Key {

	    private String certId;
	    private PublicKey pubKey;
	    private PrivateKey priKey;

	    public String getCertId() {
	        return certId;
	    }

	    public PublicKey getPubKey() {
	        return pubKey;
	    }

	    public PrivateKey getPriKey() {
	        return priKey;
	    }

		public void setCertId(String certId) {
			this.certId = certId;
		}

		public void setPubKey(PublicKey pubKey) {
			this.pubKey = pubKey;
		}

		public void setPriKey(PrivateKey priKey) {
			this.priKey = priKey;
		}

		@Override
		public String toString() {
			return "key: certId="  + certId;
		}
	}

	private static ConcurrentHashMap<String, Key> verifyCertsSnMap = new ConcurrentHashMap<String, Key>();
	private static ConcurrentHashMap<String, Key> signCertsPathMap = new ConcurrentHashMap<String, Key>();
    private static ConcurrentHashMap<String, Key> signCertsSnMap = new ConcurrentHashMap<String, Key>();
	private static Key encryptCert = null;
	private static Key pinEncryptCert = null;
    private static ConcurrentHashMap<String, X509Certificate> verifyCerts510 = new ConcurrentHashMap<String, X509Certificate>();
	private static X509Certificate middleCert = null;
	private static X509Certificate rootCert = null;
	
	static{
		addProvider();
		init();
	}
	
	/**
	 * 添加签名，验签，加密算法提供者
	 */
	private static void addProvider(){
		if (Security.getProvider("BC") == null) {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		} else {
			Security.removeProvider("BC"); //解决eclipse调试时tomcat自动重新加载时，BC存在不明原因异常的问题。
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		}
	}
	
    /**
     * 如果需要改用其他properties文件，可以调这个，默认用Config类默认使用调文件。

     */
	public static void init(){
		verifyCertsSnMap.clear();
		signCertsPathMap.clear();
	    signCertsSnMap.clear();
		getSignKey();
		initVerifySignCerts();
		initEncryptCert();
		initPinEncryptCert();
		initMiddleCert();//初始化验签证书的中级证书
		initRootCert();//初始化验签证书的根证书
	}

	/**
	 * 用配置文件acp_sdk.properties配置路径 加载5.1验签证书中级证书
	 */
	private static void initMiddleCert() {
        String path = GmSDKConfig.getConfig().getMiddleCertPath();
        if(isEmpty(path)){
            return;
        }
        middleCert = CertUtil.readX509Cert(path);
	}

	/**
     * 用配置文件acp_sdk.properties配置路径 加载5.1验签证书根证书
	 */
	private static void initRootCert() {
        String path = GmSDKConfig.getConfig().getRootCertPath();
        if(isEmpty(path)){
            return;
        }
        rootCert = CertUtil.readX509Cert(path);
	}
	
	private static void initVerifySignCerts(){
		String dir = GmSDKConfig.getConfig().getValidateCertDir();
		ConcurrentHashMap<String, Key> tmpVerifyCerts = new ConcurrentHashMap<String, Key>();
		if (dir == null || dir.trim().length() == 0) {
			return;
		}
		CertificateFactory cf = null;
		FileInputStream in = null;
		try {
			cf = CertificateFactory.getInstance("X.509", "BC");
		} catch (Exception e) {
			return ;
		}
		File fileDir = new File(dir);
		File[] files = fileDir.listFiles(new CerFilter());
		for (int i = 0; i < files.length; i++) {
			File file = files[i];
			try {
				in = new FileInputStream(file.getAbsolutePath());
				X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
				if(cert == null) {
					continue;
				}
				Key key = new Key();
				key.setCertId(cert.getSerialNumber().toString(10));
				key.setPubKey(cert.getPublicKey());
				tmpVerifyCerts.put(key.getCertId(), key);
				// 打印证书加载信息,供测试阶段调试
			} catch (CertificateException e) {
			}catch (FileNotFoundException e) {
			}catch (Exception e) {
			}finally {
				if (null != in) {
					try {
						in.close();
					} catch (IOException e) {
					}
				}
			}
		}
		if(tmpVerifyCerts != null && tmpVerifyCerts.size() > 0){
			verifyCertsSnMap = tmpVerifyCerts;
		}
	}
	
	/**
	 * 证书文件过滤器
	 * 
	 */
	static class CerFilter implements FilenameFilter {
		public boolean isCer(String name) {
			if (name.toLowerCase().endsWith(".cer")) {
				return true;
			} else {
				return false;
			}
		}
		public boolean accept(File dir, String name) {
			return isCer(name);
		}
	}
	
	private static Key getVerifySignKey(String certId){
		if(certId == null)
			throw new IllegalArgumentException("null argument");
		if(!verifyCertsSnMap.containsKey(certId))
			initVerifySignCerts();
		if(verifyCertsSnMap.containsKey(certId))
			return verifyCertsSnMap.get(certId);
		return null;
	}

	public static PublicKey getValidatePublicKey(String certId){
		return getVerifySignKey(certId).getPubKey();
	}
	
	private static void initEncryptCert(){
        String path = GmSDKConfig.getConfig().getEncryptCertPath();
        if(isEmpty(path)){
            return;
        }
        encryptCert = readGmPubCert(path);
	}
	
	private static void initPinEncryptCert(){
        String path = GmSDKConfig.getConfig().getPinEncryptCertPath();
        if(isEmpty(path)){
            return;
        }
        pinEncryptCert = readGmPubCert(path);
	}
	
	
//	public static PublicKey getEncryptCertPublicKey(){
//		return getEncryptKey(GmSDKConfig.getConfig().getEncryptCertPath()).getPubKey();
//	}
//	
//	public static String getEncryptCertId(){
//		return getEncryptKey(GmSDKConfig.getConfig().getEncryptCertPath()).getCertId();
//	}
	
	public static Key getEncryptCert(){
    	if(GmCertUtil.encryptCert == null) {
            initEncryptCert();
    	}
    	return GmCertUtil.encryptCert;
	}
	
	/**
	 * 获取敏感信息加密证书PublicKey
	 * 
	 * @return
	 */
	public static Key getPinEncryptCert() {
    	if(GmCertUtil.pinEncryptCert == null) {
            initPinEncryptCert();
    	}
    	return GmCertUtil.pinEncryptCert;
	}

	/**
	 * 
	 * @param certFilePath
	 * @param certPwd
	 */
	private static Key getSignKeyByPath(String certFilePath, String certPwd) {
		if(certFilePath == null || certPwd == null)
			throw new IllegalArgumentException("null argument");
		if(!signCertsPathMap.containsKey(certFilePath)){
			Key key = readGmPriCert(certFilePath, certPwd);
			if(key != null) {
                signCertsPathMap.put(certFilePath, key);
                signCertsSnMap.put(key.getCertId(), key);
            }
		}
		return signCertsPathMap.get(certFilePath);
	}

    /**
     *
     * @return
     */
    private static Key getSignKey() {
		String path = GmSDKConfig.getConfig().getSignCertPath();
		String pwd = GmSDKConfig.getConfig().getSignCertPwd();
        if(path == null || pwd == null) {
            return null;
        }
        return getSignKeyByPath(path, pwd);
    }
    
    public static String getSignCertId() {
		return getSignKey().getCertId();
	}
    
    public static PrivateKey getSignCertPrivateKey() {
		return getSignKey().getPriKey();
	}
    
    public static String getCertIdByKeyStoreMap(String path, String pwd) {
		return getSignKeyByPath(path, pwd).getCertId();
	}
    
    public static PrivateKey getSignCertPrivateKey(String path, String pwd) {
		return getSignKeyByPath(path, pwd).getPriKey();
	}

    private static Key readGmPriCert(String pfxkeyfile, String pwd) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(pfxkeyfile);
            byte[] bs = IOUtils.toByteArray(fis);
            bs = Base64.decodeBase64(bs);
            GmUtil.Sm2Cert cert = GmUtil.readSm2File(bs, pwd);
            Key key = new Key();
            key.setCertId(new BigInteger(cert.getCertId(), 10).toString(10));
            key.setPriKey(cert.getPrivateKey());
            return key;
        } catch (Exception e) {
            return null;
        } finally {
            if(null != fis)
                try {
                    fis.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
        }
    }
	
    private static Key readGmPubCert(String path) {
    	FileInputStream in = null;
    	try {
    		in = new FileInputStream(path);
    		CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
			X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
			if(cert == null) {
				return null;
			}
			Key key = new Key();
			key.setCertId(cert.getSerialNumber().toString(10));
			key.setPubKey(cert.getPublicKey());
			// 打印证书加载信息,供测试阶段调试
			return key;
		} catch (CertificateException e) {
		}catch (FileNotFoundException e) {
		}catch (Exception e) {
		}finally {
			if (null != in) {
				try {
					in.close();
				} catch (IOException e) {
				}
			}
		}
		return null;
	}

    public static X509Certificate verifyAndGetVerifyPubKey(String x509CertString){

        if(isEmpty(x509CertString)) {
            return null;
        }
        if(verifyCerts510.containsKey(x509CertString))
            return verifyCerts510.get(x509CertString);

        X509Certificate x509Cert = CertUtil.genCertificateByStr(x509CertString);
        if (x509Cert == null) {
            return null;
        }
        // 验证证书链
        if (!GmCertUtil.verifyCertificate(x509Cert)) {
            return null;
        }
        verifyCerts510.put(x509CertString, x509Cert);
        return x509Cert;
    }

    /**
     *
     * @param cert
     * @return
     */
    private static boolean verifyCertificate(X509Certificate cert) {
		
		if ( null == cert) {
			return false;
		}
		try {
			cert.checkValidity();//验证有效期
			if(!CertUtil.verifyCertificateChain(cert, middleCert, rootCert)){
				return false;
			}
		} catch (Exception e) {
			return false;
		}
		
		if(GmSDKConfig.getConfig().isIfValidateCNName()){
			// 验证公钥是否属于银联
			if(!UNIONPAY_CNNAME.equals(CertUtil.getIdentitiesFromCertficate(cert))) {
				return false;
			}
		} else {
			// 验证公钥是否属于银联
			if(!UNIONPAY_CNNAME.equals(CertUtil.getIdentitiesFromCertficate(cert)) 
					&& !"ZunionpayTest".equals(CertUtil.getIdentitiesFromCertficate(cert))) {
				return false;
			}
		}
		return true;		
	}

    /**
	 * 重置敏感信息加密证书公钥
	 */
	public static int resetEncryptCertPublicKey(String strCert) {
        if (isEmpty(strCert)) {
            return -1;
        }

        X509Certificate x509Cert = CertUtil.genCertificateByStr(strCert);
        // 没换，不需要更新
        if (GmCertUtil.getEncryptCert().certId.equals(
                x509Cert.getSerialNumber().toString(10))) {
            return 0;
        }

        final String localCertPath = GmSDKConfig.getConfig().getEncryptCertPath();
        if(isEmpty(localCertPath)){
            return -1;
        }
        File f = new File(localCertPath);
        if(!f.exists()) {
        } else {
            // 将本地证书进行备份存储
            int i = localCertPath.lastIndexOf(POINT);
            String leftFileName = localCertPath.substring(0, i);
            String rightFileName = localCertPath.substring(i + 1);
            String newFileName = leftFileName + "_backup" + POINT + rightFileName;
            try {
                FileUtils.copyFile(f, new File(newFileName));
            } catch (IOException e) {
                return -1;
            }
        }
        // 备份成功,进行新证书的存储
        try {
            FileUtils.writeByteArrayToFile(f, strCert.getBytes(), false);
            initEncryptCert();
            return 1;
        } catch (IOException e) {
            return -1;
        }
    }

	/**
	 * 重置pin敏感信息加密证书公钥
	 */
	public static int resetPinEncryptCertPublicKey(String strCert) {
		if (isEmpty(strCert)) {
			return -1;
		}

		X509Certificate x509Cert = CertUtil.genCertificateByStr(strCert);
		// 没换，不需要更新
		if (GmCertUtil.getPinEncryptCert().certId.equals(
				x509Cert.getSerialNumber().toString(10))) {
			return 0;
		}

		final String localCertPath = GmSDKConfig.getConfig().getPinEncryptCertPath();
		if(isEmpty(localCertPath)){
			return -1;
		}
		File f = new File(localCertPath);
		if(!f.exists()) {
		} else {
			// 将本地证书进行备份存储
			int i = localCertPath.lastIndexOf(POINT);
			String leftFileName = localCertPath.substring(0, i);
			String rightFileName = localCertPath.substring(i + 1);
			String newFileName = leftFileName + "_backup" + POINT + rightFileName;
			try {
				FileUtils.copyFile(f, new File(newFileName));
			} catch (IOException e) {
				return -1;
			}
		}
		// 备份成功,进行新证书的存储
		try {
			FileUtils.writeByteArrayToFile(f, strCert.getBytes(), false);
			initPinEncryptCert();
			return 1;
		} catch (IOException e) {
			return -1;
		}
	}
	
}
