/*
 * RSA
 * key usage						=	KU
 * subject directory attributes		=	SDA
 * inhibit any policy				=	IAP
 */
package implementation;

import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Vector;
import java.util.regex.Pattern;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DLSet;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.DirectoryString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.MiscPEMGenerator;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

import code.GuiException;
import x509.v3.CodeV3;
import gui.Constants;
import gui.GuiInterfaceV1;

import java.io.*;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.*;

public class MyCode extends CodeV3 {
	private static final boolean inhibitCnt = true;
	private static final boolean subjectCnt = true;
	private static final boolean keyCnt = true;
	private static final boolean criticalCnt = true;
	private KeyStore keyStore;
	private char[] password = "root".toCharArray();
	private PKCS10CertificationRequest csr;

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);

		try {
			keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(null, null);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Security.addProvider(new BouncyCastleProvider());
		csr = null;
	}

	@Override
	public boolean canSign(String keypair_name) {
		try {
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(keypair_name);
			if (cert.getBasicConstraints() == -1)
				return false;
			return true;
		} catch (Exception e) {

			e.printStackTrace();
			return false;
		}

	}

	@Override
	public boolean exportCSR(String file, String keypair_name, String algorithm) {
		if (!file.matches(".*.csr"))
			file += ".csr";
		try {
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(keypair_name);
			/*
			 * KeyPairGenerator gen = KeyPairGenerator.getInstance(algorithm); KeyPair pair
			 * = gen.generateKeyPair(); PrivateKey privateKey = pair.getPrivate(); PublicKey
			 * publicKey = pair.getPublic();
			 */
			PrivateKey PR = (PrivateKey) keyStore.getKey(keypair_name, password);
			PublicKey PU = cert.getPublicKey();

			X500Principal subject = new X500Principal(getSubjectInfo(keypair_name));

			ContentSigner signGen = new JcaContentSignerBuilder(algorithm).build(PR);

			PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, PU);
			csr = builder.build(signGen);
			JcaPEMWriter out = new JcaPEMWriter(new FileWriter(file));

			out.writeObject(csr);

			out.flush();
			out.close();
			return true;
		} catch (Exception e) {
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

			if (encoding == 1) {
				JcaPEMWriter pem = new JcaPEMWriter(new FileWriter(file));

				if (format == 1) {
					Certificate[] exportChain = (Certificate[]) keyStore.getCertificateChain(keypair_name);
					for (Certificate tmp : exportChain)
						pem.writeObject(tmp);
				} else
					pem.writeObject(export);
				pem.flush();
				pem.close();
			} else {
				OutputStream fileWrite = new FileOutputStream(file);
				fileWrite.write(export.getEncoded());
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
			Certificate[] chain = (Certificate[]) keyStore.getCertificateChain(keypair_name);
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
			StringBuilder ret = new StringBuilder("");
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(keypair_name);
			JcaX509CertificateHolder cHolder = new JcaX509CertificateHolder(cert);
			X500Name sub = cHolder.getSubject();

			// C, S, L, O, OU, CN, SA
			boolean flag = false;
			for (RDN tmp : sub.getRDNs()) {
				AttributeTypeAndValue t = tmp.getFirst();
				ASN1ObjectIdentifier tt = t.getType();
				ASN1Encodable tv = t.getValue();

				if (tt == BCStyle.CN.intern())
					ret.append((flag ? "," : "") + "CN=");
				else if (tt == BCStyle.C.intern())
					ret.append((flag ? "," : "") + "C=");
				else if (tt == BCStyle.L.intern())
					ret.append((flag ? "," : "") + "L=");
				else if (tt == BCStyle.O.intern())
					ret.append((flag ? "," : "") + "O=");
				else if (tt == BCStyle.ST.intern())
					ret.append((flag ? "," : "") + "ST=");
				else if (tt == BCStyle.OU.intern())
					ret.append((flag ? "," : "") + "OU=");
				ret.append(tv.toString());
				flag = true;
			}
			return ret.toString();
		} catch (Exception e) {

			e.printStackTrace();
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	@Override
	public boolean importCAReply(String file, String keypair_name) {
		try {
			FileInputStream in = new FileInputStream(new File(file));
			CertificateFactory fact = CertificateFactory.getInstance("X509");
			Collection<X509Certificate> coll = (Collection<X509Certificate>) fact.generateCertificates(in);
			Iterator<X509Certificate> it = (Iterator<X509Certificate>) coll.iterator();

			PrivateKey PR = (PrivateKey) keyStore.getKey(keypair_name, password);

			Certificate[] chain = new Certificate[2];

			chain[0] = it.next();
			chain[1] = it.next();
			// keyStore.deleteEntry(keypair_name);
			keyStore.setKeyEntry(keypair_name, PR, password, chain);

			loadKeypair(keypair_name);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public String importCSR(String file) {
		PKCS10CertificationRequest tempCsr = null;
		StringBuilder ret = new StringBuilder("");
		try {

			Reader pemReader = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
			PEMParser pemParser = new PEMParser(pemReader);
			Object parsedObj = pemParser.readObject();

			if (parsedObj instanceof PKCS10CertificationRequest) {
				tempCsr = (PKCS10CertificationRequest) parsedObj;
			}
			pemParser.close();
			pemReader.close();

			if (tempCsr == null)
				return null;
			csr = tempCsr;
			X500Name sub = csr.getSubject();
			boolean flag = false;

			for (RDN tmp : sub.getRDNs()) {
				AttributeTypeAndValue t = tmp.getFirst();
				ASN1ObjectIdentifier tt = t.getType();
				ASN1Encodable tv = t.getValue();

				if (tt == BCStyle.CN.intern())
					ret.append((flag ? "," : "") + "CN=");
				else if (tt == BCStyle.C.intern())
					ret.append((flag ? "," : "") + "C=");
				else if (tt == BCStyle.L.intern())
					ret.append((flag ? "," : "") + "L=");
				else if (tt == BCStyle.O.intern())
					ret.append((flag ? "," : "") + "O=");
				else if (tt == BCStyle.ST.intern())
					ret.append((flag ? "," : "") + "ST=");
				else if (tt == BCStyle.OU.intern())
					ret.append((flag ? "," : "") + "OU=");
				ret.append(tv.toString());
				flag = true;
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret.toString();
	}

	@Override
	
	public boolean importCertificate(String file, String keypair_name) {
		if (!file.matches(".*.cer"))
			return false;
		InputStream inStream = null;
		try {

			inStream = new FileInputStream(new File(file));
			CertificateFactory cf = CertificateFactory.getInstance("X.509");

			X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
			inStream.close();

			keyStore.setCertificateEntry(keypair_name, cert);
			loadKeypair(keypair_name);
			return true;
		} catch (Exception e) {
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
			f.close();
			keyStore.setKeyEntry(keypair_name, ks.getKey(keypair_name, password.toCharArray()), this.password,
					ks.getCertificateChain(keypair_name));

		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@SuppressWarnings("unchecked")
	@Override
	public int loadKeypair(String keypair_name) {

		try {

			X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keypair_name);

			access.setNotBefore(certificate.getNotBefore());
			access.setNotAfter(certificate.getNotAfter());
			access.setSerialNumber(certificate.getSerialNumber().toString());
			access.setVersion(certificate.getVersion() - 1);
			JcaX509CertificateHolder cHolder = new JcaX509CertificateHolder(certificate);

			access.setPublicKeyAlgorithm(getCertPublicKeyAlgorithm(keypair_name));
			access.setPublicKeyParameter(getCertPublicKeyParameter(keypair_name));
			access.setPublicKeyDigestAlgorithm(certificate.getSigAlgName());
			access.setSubjectSignatureAlgorithm(certificate.getPublicKey().getAlgorithm());

			access.setIssuer(certificate.getIssuerDN().toString().replaceAll(", ", ","));
			access.setIssuerSignatureAlgorithm(certificate.getSigAlgName());

			X500Name sub = cHolder.getSubject();
			for (RDN tmp : sub.getRDNs()) {
				AttributeTypeAndValue t = tmp.getFirst();
				ASN1ObjectIdentifier tt = t.getType();
				ASN1Encodable tv = t.getValue();

				if (tt == BCStyle.CN.intern())
					access.setSubjectCommonName(tv.toString());
				else if (tt == BCStyle.C.intern())
					access.setSubjectCountry(tv.toString());
				else if (tt == BCStyle.L.intern())
					access.setSubjectLocality(tv.toString());
				else if (tt == BCStyle.O.intern())
					access.setSubjectOrganization(tv.toString());
				else if (tt == BCStyle.ST.intern())
					access.setSubjectState(tv.toString());
				else if (tt == BCStyle.OU.intern())
					access.setSubjectOrganizationUnit(tv.toString());
			}
			if (criticalCnt) {
				// Critical
				for (String tmp : certificate.getCriticalExtensionOIDs()) {
					if (keyCnt && tmp.equals(Extension.keyUsage.toString()))
						access.setCritical(Constants.KU, true);
					if (subjectCnt && tmp.equals(Extension.subjectDirectoryAttributes.toString()))
						access.setCritical(Constants.SDA, true);
					if (inhibitCnt && tmp.equals(Extension.inhibitAnyPolicy.toString()))
						access.setCritical(Constants.IAP, true);
				}
			}
			if (keyCnt) {
				// Key Usage
				boolean[] key = certificate.getKeyUsage();
				if (key != null)
					access.setKeyUsage(certificate.getKeyUsage());

			}
			if (subjectCnt) {
				// Subject Directory Attribute
				Extension ext;
				if ((ext = cHolder.getExtension(Extension.subjectDirectoryAttributes)) != null) {
					Vector<Attribute> vect = (Vector<Attribute>) SubjectDirectoryAttributes
							.getInstance(ext.getParsedValue()).getAttributes();
					for (Attribute tmp : vect) {
						if (tmp.getAttrType().toString().equals(BCStyle.COUNTRY_OF_CITIZENSHIP.toString()))
							access.setSubjectDirectoryAttribute(Constants.COC, tmp.getAttributeValues()[0].toString());
						if (tmp.getAttrType().toString().equals(BCStyle.PLACE_OF_BIRTH.toString()))
							access.setSubjectDirectoryAttribute(Constants.POB, tmp.getAttributeValues()[0].toString());
						if (tmp.getAttrType().toString().equals(BCStyle.GENDER.toString()))
							access.setGender(tmp.getAttributeValues()[0].toString());
						if (tmp.getAttrType().toString().equals(BCStyle.DATE_OF_BIRTH.toString()))
							access.setDateOfBirth(tmp.getAttributeValues()[0].toString());
					}
				}
			}
			if (inhibitCnt) {
				// Inhibit any policy
				Extension ext;
				if ((ext = cHolder.getExtension(Extension.inhibitAnyPolicy)) != null) {
					access.setInhibitAnyPolicy(true);
					access.setSkipCerts(ASN1Integer.getInstance(ext.getParsedValue()) + "");
				}
			}
			

			if (keyStore.isCertificateEntry(keypair_name))
				return 2;
			if (!(new JcaX509CertificateHolder(certificate).getSubject().toString())
					.equals(new JcaX509CertificateHolder(certificate).getIssuer().toString()))
				return 1;

		} catch (

		Exception ex) {
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
				keyStore.load(new FileInputStream("local.p12"), password);
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

		return true;
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
	public boolean saveKeypair(String keypair_name) {

		try {

			if (access.getVersion() != Constants.V3)
				return false;
			
			CertificateFactory.getInstance("X.509");
			KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
			g.initialize(Integer.parseInt(access.getPublicKeyParameter()));
			KeyPair pair = g.generateKeyPair();
			PublicKey PU = pair.getPublic();
			PrivateKey PR = pair.getPrivate();

			X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
			nameBuilder.addRDN(BCStyle.CN, super.access.getSubjectCommonName());
			nameBuilder.addRDN(BCStyle.O, super.access.getSubjectOrganization());
			nameBuilder.addRDN(BCStyle.OU, super.access.getSubjectOrganizationUnit());
			nameBuilder.addRDN(BCStyle.L, super.access.getSubjectLocality());
			nameBuilder.addRDN(BCStyle.ST, super.access.getSubjectState());
			nameBuilder.addRDN(BCStyle.C, super.access.getSubjectCountry());

			Date before = access.getNotBefore();
			Date after = access.getNotAfter();
			BigInteger serial = new BigInteger(access.getSerialNumber());

			X500Name issuer = nameBuilder.build();
			X500Name subject = issuer;

			X509v3CertificateBuilder generator = new JcaX509v3CertificateBuilder(issuer, serial, before, after, subject,
					PU);
			if (keyCnt) {
				// key usage extension
				boolean[] ku = access.getKeyUsage();
				boolean kuCrit = access.isCritical(Constants.KU);
				int usage = 0;
				for (int i = 0; i < 9; i++) {
					if (ku[i])
						switch (i) {
						case 0:
							usage |= KeyUsage.digitalSignature;
							break;
						case 1:
							usage |= KeyUsage.nonRepudiation;
							break;
						case 2:
							usage |= KeyUsage.keyEncipherment;
							break;
						case 3:
							usage |= KeyUsage.dataEncipherment;
							break;
						case 4:
							usage |= KeyUsage.keyAgreement;
							break;
						case 5:
							usage |= KeyUsage.keyCertSign;
							break;
						case 6:
							usage |= KeyUsage.cRLSign;
							break;
						case 7:
							usage |= KeyUsage.encipherOnly;
							break;
						case 8:
							usage |= KeyUsage.decipherOnly;
							break;
						}
				}

				KeyUsage KU = new KeyUsage(usage);
				generator.addExtension(Extension.keyUsage, kuCrit, KU);
			}
			if (subjectCnt) {
				// subject directory attributes extension
				String sda_pob = access.getSubjectDirectoryAttribute(Constants.POB);
				String sda_coc = access.getSubjectDirectoryAttribute(Constants.COC);
				String sda_gen = access.getGender();
				String sda_date = access.getDateOfBirth();
				boolean sdaCrit = access.isCritical(Constants.SDA);

				Vector<Attribute> vect = new Vector<Attribute>();

				if (!sda_coc.equals(""))
					vect.add(new Attribute(BCStyle.COUNTRY_OF_CITIZENSHIP, new DLSet(new DirectoryString(sda_coc))));
				if (!sda_pob.equals(""))
					vect.add(new Attribute(BCStyle.PLACE_OF_BIRTH, new DLSet(new DirectoryString(sda_pob))));
				if (!sda_gen.equals(""))
					vect.add(new Attribute(BCStyle.GENDER, new DLSet(new DirectoryString(sda_gen))));
				if (!sda_date.equals(""))
					vect.add(new Attribute(BCStyle.DATE_OF_BIRTH, new DLSet(new DirectoryString(sda_date))));

				SubjectDirectoryAttributes SDA = new SubjectDirectoryAttributes(vect);
				generator.addExtension(Extension.subjectDirectoryAttributes, sdaCrit, SDA);
			}
			if (inhibitCnt) {
				// inhibit any policy extension boolean
				boolean iap = access.getInhibitAnyPolicy();
				boolean iapCrit = access.isCritical(Constants.IAP);
				if (iap) {
					int skipCerts;
					if (access.getSkipCerts().equals("") || access.getSkipCerts().charAt(0) == '-')
						skipCerts = Integer.MAX_VALUE;
					else
						skipCerts = Integer.parseInt(access.getSkipCerts());

					ASN1Integer IAP = new ASN1Integer(skipCerts);
					generator.addExtension(Extension.inhibitAnyPolicy, iapCrit, IAP);
				}
			}

			ContentSigner signer = new JcaContentSignerBuilder(access.getPublicKeyDigestAlgorithm()).build(PR);
			X509CertificateHolder holder = generator.build(signer);
			X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
			X509Certificate[] chain = new X509Certificate[1];
			chain[0] = cert;

			keyStore.setKeyEntry(keypair_name, PR, password, chain);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public boolean signCSR(String file, String keypair_name, String algorithm) {

		if (!file.matches(".*.p7(b|c)"))
			file += ".p7b";
		try {
			X509CertificateHolder issuerHolder = new JcaX509CertificateHolder(
					(X509Certificate) keyStore.getCertificate(keypair_name));
			X509v3CertificateBuilder builder = new X509v3CertificateBuilder(issuerHolder.getSubject(),
					new BigInteger(access.getSerialNumber()), access.getNotBefore(), access.getNotAfter(),
					csr.getSubject(), csr.getSubjectPublicKeyInfo());
			if (keyCnt) {
				// key usage extension
				boolean[] ku = access.getKeyUsage();
				boolean kuCrit = access.isCritical(Constants.KU);
				int usage = 0;

				for (int i = 0; i < 9; i++) {
					if (ku[i])
						switch (i) {
						case 0:
							usage |= KeyUsage.digitalSignature;
							break;
						case 1:
							usage |= KeyUsage.nonRepudiation;
							break;
						case 2:
							usage |= KeyUsage.keyEncipherment;
							break;
						case 3:
							usage |= KeyUsage.dataEncipherment;
							break;
						case 4:
							usage |= KeyUsage.keyAgreement;
							break;
						case 5:
							usage |= KeyUsage.keyCertSign;
							break;
						case 6:
							usage |= KeyUsage.cRLSign;
							break;
						case 7:
							usage |= KeyUsage.encipherOnly;
							break;
						case 8:
							usage |= KeyUsage.decipherOnly;
							break;
						}
				}
				if ((usage & KeyUsage.digitalSignature) == 0) {
					GuiInterfaceV1.reportError("Digital signature is not checked! ");
					return false;
				}
				KeyUsage KU = new KeyUsage(usage);
				builder.addExtension(Extension.keyUsage, kuCrit, KU);
			}
			if (subjectCnt) {
				// subject directory attributes extension
				String sda_pob = access.getSubjectDirectoryAttribute(Constants.POB);
				String sda_coc = access.getSubjectDirectoryAttribute(Constants.COC);
				String sda_gen = access.getGender();
				String sda_date = access.getDateOfBirth();
				boolean sdaCrit = access.isCritical(Constants.SDA);
				if (sdaCrit) {
					GuiInterfaceV1.reportError("Extension: 'Subject directory attributes' is critical! ");
					return false;
				}
				Vector<Attribute> vect = new Vector<Attribute>();

				if (!sda_coc.equals(""))
					vect.add(new Attribute(BCStyle.COUNTRY_OF_CITIZENSHIP, new DLSet(new DirectoryString(sda_coc))));
				if (!sda_pob.equals(""))
					vect.add(new Attribute(BCStyle.PLACE_OF_BIRTH, new DLSet(new DirectoryString(sda_pob))));
				if (!sda_gen.equals(""))
					vect.add(new Attribute(BCStyle.GENDER, new DLSet(new DirectoryString(sda_gen))));
				if (!sda_date.equals(""))
					vect.add(new Attribute(BCStyle.DATE_OF_BIRTH, new DLSet(new DirectoryString(sda_date))));

				SubjectDirectoryAttributes SDA = new SubjectDirectoryAttributes(vect);
				builder.addExtension(Extension.subjectDirectoryAttributes, sdaCrit, SDA);
			}
			if (inhibitCnt) {
				// inhibit any policy extension
				boolean iap = access.getInhibitAnyPolicy();
				if (iap) {
					GuiInterfaceV1.reportError("Extension: 'Inhibit anyPolicy' is not supported ");
					return false;
				}
				boolean iapCrit = access.isCritical(Constants.IAP);
				if (iap) {
					int skipCerts;
					if (access.getSkipCerts().equals("") || access.getSkipCerts().charAt(0) == '-')
						skipCerts = Integer.MAX_VALUE;
					else
						skipCerts = Integer.parseInt(access.getSkipCerts());

					ASN1Integer IAP = new ASN1Integer(skipCerts);
					builder.addExtension(Extension.inhibitAnyPolicy, iapCrit, IAP);
				}
			}

			ContentSigner signer = new JcaContentSignerBuilder(algorithm)
					.build((PrivateKey) keyStore.getKey(keypair_name, password));

			byte[] encoded = builder.build(signer).getEncoded();
			X509CertificateHolder cHolder = new X509CertificateHolder(encoded);

			CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

			generator.addSignerInfoGenerator(
					new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build()).build(signer,
							(X509Certificate) keyStore.getCertificate(keypair_name)));

			generator.addCertificate(cHolder);

			Certificate[] caChain = keyStore.getCertificateChain(keypair_name);
			X509CertificateHolder CAHolder = null;
			for (Certificate tmp : caChain) {
				CAHolder = new X509CertificateHolder(tmp.getEncoded());
				generator.addCertificate(CAHolder);
			}

			CMSSignedData data = generator.generate(new CMSProcessableByteArray(encoded), true);

			FileOutputStream out = new FileOutputStream(file);
			
			out.write(data.getEncoded());
			out.close();
			return true;
		} catch (Exception e) {
			e.printStackTrace();
		}

		return false;
	}
}
