package implementation;

import java.util.Enumeration;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import code.GuiException;
import x509.v3.CodeV3;
import gui.Constants;

import java.io.*;
import java.security.*;
import java.security.KeyStore.Entry.Attribute;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.*;

public class MyCode extends CodeV3 {
	private KeyStore keyStore;
	private char[] password = "root".toCharArray();
	PKCS10CertificationRequest csr;
	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
		
		try {
			keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(null, null);
		} catch (Exception e) {	
			e.printStackTrace();
		}
		Security.addProvider(new BouncyCastleProvider());
		access.setVersion(Constants.V3);
		csr = null;
	}
	@Override
	public boolean canSign(String keypair_name) {
		try {
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(keypair_name);
			if (cert.getBasicConstraints() == -1) return false;
			return true;
		} catch (Exception e) {
			
			e.printStackTrace();
			return false;
		}
		
	}
	@Override
	public boolean exportCSR(String file, String keypair_name, String algorithm) {
		if (!file.matches(".*.csr")) file += ".csr";
		try {
			X509Certificate cert = (X509Certificate)keyStore.getCertificate(keypair_name);
			
			KeyPairGenerator gen = KeyPairGenerator.getInstance(algorithm);
			KeyPair pair = gen.generateKeyPair();
			PrivateKey privateKey = pair.getPrivate();
			PublicKey publicKey = pair.getPublic();
			X500Principal subject = new X500Principal (getCertPublicKeyParameter(keypair_name));
			
			ContentSigner signGen = new JcaContentSignerBuilder(cert.getSigAlgName()).build(privateKey);

			
			PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);
			csr = builder.build(signGen);
						
			JcaPEMWriter out = new JcaPEMWriter(new FileWriter(file));
			
			out.writeObject(csr);
			
			out.flush();
			out.close();
			return true;
		}catch(Exception e) {
			e.printStackTrace();
		}
		return false;
	}
	@Override
	public boolean exportCertificate(String file, String keypair_name, int encoding, int format) {
		try {
			if (!file.matches(".*.cer"))
				file += ".cer";
			
			X509Certificate export = (X509Certificate) keyStore.getCertificate(keypair_name);
			JcaX509CertificateHolder cert = new JcaX509CertificateHolder(export);
			X509Certificate[] exportChain = null;
			if (format == 1)
				exportChain = (X509Certificate[]) keyStore.getCertificateChain(keypair_name);
			if (encoding == 1) {
				JcaPEMWriter pemWrt = new JcaPEMWriter(new FileWriter(file));
				if (format == 1)
					pemWrt.writeObject(exportChain);
				else
					pemWrt.writeObject(export);
				pemWrt.flush();
				pemWrt.close();
			} else {
				DEROutputStream fileWrite = new DEROutputStream(new FileOutputStream(file));
				if (format == 1)
					for (X509Certificate tmp : exportChain)
						fileWrite.writeObject((ASN1Encodable)new JcaX509CertificateHolder(tmp));
				else
					fileWrite.writeObject((ASN1Encodable)cert);
				fileWrite.flush();
				fileWrite.close();
			}

		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
	@Override
	public boolean exportKeypair(String keypair_name, String file, String password) {
		if (!file.matches(".*.p12"))
			file += ".p12";
		try {
			FileOutputStream out = new FileOutputStream(file);

			KeyStore newKeyStore = KeyStore.getInstance("PKCS12");
			newKeyStore.load(null, null);
			X509Certificate[] chain = (X509Certificate[]) keyStore.getCertificateChain(keypair_name);
			newKeyStore.setKeyEntry(keypair_name, keyStore.getKey(keypair_name, this.password), password.toCharArray(),
					chain);
			newKeyStore.store(out, password.toCharArray());

			out.close();
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
	@Override
	public String getCertPublicKeyAlgorithm(String keypair_name) {
		try {
			String s = keyStore.getCertificate(keypair_name).getPublicKey().getAlgorithm();
			if (s.equals("DSA") || s.equals("RSA") || s.equals("EC"))
				return s;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	@Override
	public String getCertPublicKeyParameter(String keypair_name) {
		String ret = new String("");
		try {
			PublicKey pk = keyStore.getCertificate(keypair_name).getPublicKey();
			String alg = pk.getAlgorithm();
			if (alg.equals("EC"))
				ret = ((ECPublicKey) pk).getParameters().getCurve().toString();
			else if (alg.equals("DSA"))
				ret += ((DSAPublicKey) pk).getY().bitLength();
			else if (alg.equals("RSA"))
				ret += ((RSAPublicKey) pk).getModulus().bitLength();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}
	@Override
	public String getSubjectInfo(String keypair_name) {		
		try {
			String ret = new String("");
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(keypair_name);
			JcaX509CertificateHolder cHolder = new JcaX509CertificateHolder(cert);
			X500Name sub = cHolder.getSubject();
			//C, S, L, O, OU, CN, SA
			ret = "C="+ sub.getRDNs(BCStyle.C)[0].toString() + ""
					+ " S=" +sub.getRDNs(BCStyle.ST)[0].toString() + ""
					+ " L=" + sub.getRDNs(BCStyle.L)[0].toString() + ""
					+ " O=" + sub.getRDNs(BCStyle.O)[0].toString() + ""
					+ " OU =" + sub.getRDNs(BCStyle.OU)[0].toString() + ""
					+ " CN=" + sub.getRDNs(BCStyle.CN)[0].toString();
			return ret;
		} catch (Exception e) {
			
			e.printStackTrace();
		}
		return null;
	}
	@Override
	public boolean importCAReply(String arg0, String arg1) {
		
		return false;
	}
	@Override
	public String importCSR(String file) {
		PKCS10CertificationRequest tempCsr = null;
		String ret = null;
		try {

			Reader pemReader = new BufferedReader(new InputStreamReader(new FileInputStream(new File(file))));	
			PEMParser pemParser = new PEMParser(pemReader);
	        Object parsedObj = pemParser.readObject();

	        if (parsedObj instanceof PKCS10CertificationRequest) {
	        	tempCsr = (PKCS10CertificationRequest) parsedObj;
	        }
	        pemParser.close();
	        pemReader.close();
	        if (tempCsr == null) return null;
	        csr = tempCsr;
	        X500Name sub = csr.getSubject();
	        ret = "C="+ sub.getRDNs(BCStyle.C)[0].toString() + ""
					+ " S=" +sub.getRDNs(BCStyle.ST)[0].toString() + ""
					+ " L=" + sub.getRDNs(BCStyle.L)[0].toString() + ""
					+ " O=" + sub.getRDNs(BCStyle.O)[0].toString() + ""
					+ " OU =" + sub.getRDNs(BCStyle.OU)[0].toString() + ""
					+ " CN=" + sub.getRDNs(BCStyle.CN)[0].toString();
			
		}catch(Exception e) {
			e.printStackTrace();
		}
		return ret;
	}
	@Override
	public boolean importCertificate(String file, String keypair_name) {
		if (!file.matches(".*.cer")) return false;
		InputStream inStream = null;
		try {
			
			inStream = new FileInputStream(file);
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
			keyStore.setCertificateEntry(keypair_name, cert);
			inStream.close();
			return true;
		}catch(Exception e) {
			e.printStackTrace();
		}
		return false;
	}
	@Override
	public boolean importKeypair(String keypair_name, String file, String password) {
		if (!file.matches(".*.p12"))
			return false;
		FileInputStream f = null;
		try {
			f = new FileInputStream(file);
			KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
			ks.load(f, password.toCharArray());
			keyStore.setKeyEntry(keypair_name, ks.getKey(keypair_name, password.toCharArray()), this.password,
					ks.getCertificateChain(keypair_name));
			f.close();
		} catch (Exception e) {
			e.printStackTrace();
			// if (f != null) f.close();
			return false;
		}
		return true;
	}
	@Override
	public int loadKeypair(String keypair_name) {
		/*
		 * -1 u slučaju greške; 0 u slučaju da sertifikat sačuvan pod tim alias-om nije
		 * potpisan; 1 u slučaju da je potpisan; 2 u slučaju da je upitanju trusted
		 * sertifikat
		 */
		try {

			X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keypair_name);

			access.setNotBefore(certificate.getNotBefore());
			access.setNotAfter(certificate.getNotAfter());
			access.setSerialNumber(certificate.getSerialNumber().toString());

			JcaX509CertificateHolder cHolder = new JcaX509CertificateHolder(certificate);

			access.setIssuer(cHolder.getIssuer().toString());
			access.setIssuerSignatureAlgorithm(cHolder.getSignatureAlgorithm().toString());

			// X500Name sub = cHolder.getSubject();

			X500Name sub = cHolder.getSubject();

			access.setSubjectCommonName(sub.getRDNs(BCStyle.CN)[0].toString());
			access.setSubjectCountry(sub.getRDNs(BCStyle.C)[0].toString());
			access.setSubjectLocality(sub.getRDNs(BCStyle.L)[0].toString());
			access.setSubjectOrganization(sub.getRDNs(BCStyle.O)[0].toString());
			access.setSubjectState(sub.getRDNs(BCStyle.ST)[0].toString());
			access.setSubjectOrganizationUnit(sub.getRDNs(BCStyle.OU)[0].toString());

			boolean[] key = certificate.getKeyUsage();
			if (key != null)
				access.setKeyUsage(certificate.getKeyUsage());

			for (String tmp : certificate.getCriticalExtensionOIDs()) {
				if (tmp.equals("KU"))
					access.setCritical(Constants.KU, true);
				if (tmp.equals("SDA"))
					access.setCritical(Constants.SDA, true);
				if (tmp.equals("IAP"))
					access.setCritical(Constants.IAP, true);
			}
			if (keyStore.isCertificateEntry(keypair_name))
				return 2;
			if (!(new JcaX509CertificateHolder(certificate).getSubject().toString())
					.equals(new JcaX509CertificateHolder(certificate).getIssuer().toString()))
				return 1;

		} catch (Exception ex) {
			ex.printStackTrace();
			return -1;
		}
		return 0;

	}
	@Override
	public Enumeration<String> loadLocalKeystore() {

		if (keyStore != null)
			try {
				keyStore = KeyStore.getInstance("PKCS12");
				keyStore.load(new FileInputStream("localKeyStore.p12"), password);
				return keyStore.aliases();
			} catch (Exception e) {
				e.printStackTrace();
			}

		return null;
	}
	@Override
	public boolean removeKeypair(String keypair_name) {

		try {
			keyStore.deleteEntry(keypair_name);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}

		return false;
	}
	@Override
	public void resetLocalKeystore() {
		try {
			Enumeration<String> e = keyStore.aliases();
			while (e.hasMoreElements()) {
				keyStore.deleteEntry(e.nextElement());
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	@Override
	public boolean saveKeypair(String arg0) {

		try {

			if (access.getVersion() != Constants.V3)
				return false;

		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
	@Override
	public boolean signCSR(String file, String keypair_name, String algorithm) {
		/*
		if (!file.matches(".*.p7(b|c)")) file += ".p7b";
		try {
			X509Certificate issuer = (X509Certificate) keyStore.getCertificate(keypair_name);
			X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, cert.getSerialNumber(),
					access.getNotBefore(), access.getNotAfter(), csr.getSubject(), cert.getPublicKey());
			
			Attribute[] attributes = (Attribute[]) csr.getAttributes();
			
			Iterator iterator = (Iterator) attributes[0].getAttrValues().iterator();
			Extensions extensions = (Extensions) iterator.next();
			ASN1ObjectIdentifier[] OIDs = extensions.getExtensionOIDs();
			for (int i = 0; i < OIDs.length; i++) {
				builder.addExtension(extensions.getExtension(OIDs[i]));
			}
			
			ContentSigner signer;
			signer = new JcaContentSignerBuilder(arg1)
					.build((PrivateKey) keyStore.getKey(arg0, "password".toCharArray()));

			X509Certificate newCert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
			X509Certificate[] issuerChain = keyStore.getCertificateChain(arg0);
			X509Certificate[] chain = new X509Certificate[issuerChain.length + 1];
			chain[0] = newCert;
			for (int i = 0; i < issuerChain.length; i++) {
				chain[i + 1] = (X509Certificate) issuerChain[i];
			}
			keyStore.setKeyEntry(selected, keyStore.getKey(selected, "password".toCharArray()),
					"password".toCharArray(), chain);
			
			return true;
		}catch(Exception e) {
			e.printStackTrace();
		}
		*/
		return false;
	}

}
