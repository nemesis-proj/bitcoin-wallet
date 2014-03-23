/*
 * Copyright 2014 the original author or authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.schildbach.wallet.util;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.x500.X500Principal;

import org.bitcoin.protocols.payments.Protos;
import org.bitcoin.protocols.payments.Protos.PaymentRequest;
import org.spongycastle.asn1.ASN1String;
import org.spongycastle.asn1.x500.AttributeTypeAndValue;
import org.spongycastle.asn1.x500.RDN;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x500.style.RFC4519Style;

import com.google.bitcoin.core.Address;
import com.google.bitcoin.core.ScriptException;
import com.google.bitcoin.core.Transaction;
import com.google.bitcoin.protocols.payments.PaymentRequestException;
import com.google.bitcoin.script.Script;
import com.google.bitcoin.script.ScriptBuilder;
import com.google.common.collect.Lists;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.UninitializedMessageException;

import de.schildbach.wallet.Constants;
import de.schildbach.wallet.PaymentIntent;
import de.schildbach.wallet.util.X509.PkiVerificationData;

/**
 * @author Andreas Schildbach
 */
public final class PaymentProtocol
{
	public static final String MIMETYPE_PAYMENTREQUEST = "application/bitcoin-paymentrequest"; // BIP 71
	public static final String MIMETYPE_PAYMENT = "application/bitcoin-payment"; // BIP 71
	public static final String MIMETYPE_PAYMENTACK = "application/bitcoin-paymentack"; // BIP 71

	public static Protos.PaymentRequest createPaymentRequest(final BigInteger amount, @Nonnull final Address toAddress, final String memo,
			final String paymentUrl, final X509Certificate[] certificateChain, final PrivateKey privateKey)
	{
		if (amount != null && amount.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) > 0)
			throw new IllegalArgumentException("amount too big for protobuf: " + amount);

		final Protos.Output.Builder output = Protos.Output.newBuilder();
		output.setAmount(amount != null ? amount.longValue() : 0);
		output.setScript(ByteString.copyFrom(ScriptBuilder.createOutputScript(toAddress).getProgram()));

		final Protos.PaymentDetails.Builder paymentDetails = Protos.PaymentDetails.newBuilder();
		paymentDetails.setNetwork(Constants.NETWORK_PARAMETERS.getPaymentProtocolId());
		paymentDetails.addOutputs(output);
		if (memo != null)
			paymentDetails.setMemo(memo);
		if (paymentUrl != null)
			paymentDetails.setPaymentUrl(paymentUrl);
		paymentDetails.setTime(System.currentTimeMillis());

		final Protos.PaymentRequest.Builder paymentRequest = Protos.PaymentRequest.newBuilder();
		paymentRequest.setSerializedPaymentDetails(paymentDetails.build().toByteString());

		if (privateKey != null)
		{
			long start = System.currentTimeMillis();

			try
			{
				final Protos.X509Certificates.Builder certificates = Protos.X509Certificates.newBuilder();
				for (final Certificate certificate : certificateChain)
					certificates.addCertificate(ByteString.copyFrom(certificate.getEncoded()));

				// TODO maybe cut cert chain?

				paymentRequest.setPkiType("x509+sha256");
				paymentRequest.setPkiData(certificates.build().toByteString());
				paymentRequest.setSignature(ByteString.EMPTY);
				final PaymentRequest paymentRequestToSign = paymentRequest.build();

				final String algorithm;
				if (privateKey.getAlgorithm().equalsIgnoreCase("RSA"))
					algorithm = "SHA256withRSA";
				else
					throw new IllegalStateException(privateKey.getAlgorithm());

				final Signature signature = Signature.getInstance(algorithm);
				signature.initSign(privateKey);
				signature.update(paymentRequestToSign.toByteArray());

				paymentRequest.setSignature(ByteString.copyFrom(signature.sign()));

				System.out.println("========================== signed, took " + (System.currentTimeMillis() - start) + " ms");
			}
			catch (final GeneralSecurityException x)
			{
				throw new RuntimeException(x);
			}
		}

		return paymentRequest.build();
	}

	public static PaymentIntent parsePaymentRequest(@Nonnull final byte[] serializedPaymentRequest) throws PaymentRequestException
	{
		try
		{
			if (serializedPaymentRequest.length > 50000)
				throw new PaymentRequestException("payment request too big: " + serializedPaymentRequest.length);

			final Protos.PaymentRequest paymentRequest = Protos.PaymentRequest.parseFrom(serializedPaymentRequest);

			final String pkiName;
			final String pkiOrgName;
			final String pkiCaName;
			if (!"none".equals(paymentRequest.getPkiType()))
			{
				// implicitly verify PKI signature
				final PkiVerificationData verificationData = verifyPki(paymentRequest);
				pkiName = verificationData.name != null ? verificationData.name : verificationData.altName;
				pkiOrgName = verificationData.orgName;
				pkiCaName = verificationData.rootAuthorityName;
			}
			else
			{
				pkiName = null;
				pkiOrgName = null;
				pkiCaName = null;
			}

			if (paymentRequest.getPaymentDetailsVersion() != 1)
				throw new PaymentRequestException.InvalidVersion("cannot handle payment details version: "
						+ paymentRequest.getPaymentDetailsVersion());

			final Protos.PaymentDetails paymentDetails = Protos.PaymentDetails.newBuilder().mergeFrom(paymentRequest.getSerializedPaymentDetails())
					.build();

			final long currentTimeSecs = System.currentTimeMillis() / 1000;
			if (paymentDetails.hasExpires() && currentTimeSecs >= paymentDetails.getExpires())
				throw new PaymentRequestException.Expired("payment details expired: current time " + currentTimeSecs + " after expiry time "
						+ paymentDetails.getExpires());

			if (!paymentDetails.getNetwork().equals(Constants.NETWORK_PARAMETERS.getPaymentProtocolId()))
				throw new PaymentRequestException.InvalidNetwork("cannot handle payment request network: " + paymentDetails.getNetwork());

			final ArrayList<PaymentIntent.Output> outputs = new ArrayList<PaymentIntent.Output>(paymentDetails.getOutputsCount());
			for (final Protos.Output output : paymentDetails.getOutputsList())
				outputs.add(parseOutput(output));

			final String memo = paymentDetails.hasMemo() ? paymentDetails.getMemo() : null;
			final String paymentUrl = paymentDetails.hasPaymentUrl() ? paymentDetails.getPaymentUrl() : null;
			final byte[] merchantData = paymentDetails.hasMerchantData() ? paymentDetails.getMerchantData().toByteArray() : null;

			final PaymentIntent paymentIntent = new PaymentIntent(PaymentIntent.Standard.BIP70, pkiName, pkiOrgName, pkiCaName,
					outputs.toArray(new PaymentIntent.Output[0]), memo, paymentUrl, merchantData, null);

			if (paymentIntent.hasPaymentUrl() && !paymentIntent.isSupportedPaymentUrl())
				throw new PaymentRequestException.InvalidPaymentURL("cannot handle payment url: " + paymentIntent.paymentUrl);

			return paymentIntent;
		}
		catch (final InvalidProtocolBufferException x)
		{
			throw new PaymentRequestException(x);
		}
		catch (final UninitializedMessageException x)
		{
			throw new PaymentRequestException(x);
		}
	}

	/**
	 * Uses the provided PKI method to find the corresponding public key and verify the provided signature. Returns null
	 * if no PKI method was specified in the {@link Protos.PaymentRequest}.
	 */
	private static @Nullable
	PkiVerificationData verifyPki(final PaymentRequest paymentRequest) throws PaymentRequestException
	{
		try
		{
			final String pkiType = paymentRequest.getPkiType();
			if (pkiType.equals("none"))
				// Nothing to verify. Everything is fine. Move along.
				return null;

			final String algorithm;
			if (pkiType.equals("x509+sha256"))
				algorithm = "SHA256withRSA";
			else if (pkiType.equals("x509+sha1"))
				algorithm = "SHA1withRSA";
			else
				throw new PaymentRequestException.InvalidPkiType("Unsupported PKI type: " + pkiType);

			Protos.X509Certificates protoCerts = Protos.X509Certificates.parseFrom(paymentRequest.getPkiData());
			if (protoCerts.getCertificateCount() == 0)
				throw new PaymentRequestException.InvalidPkiData("No certificates provided in message: server config error");

			// Parse the certs and turn into a certificate chain object. Cert factories can parse both DER and base64.
			// The ordering of certificates is defined by the payment protocol spec to be the same as what the Java
			// crypto API requires - convenient!
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			List<X509Certificate> certs = Lists.newArrayList();
			for (ByteString bytes : protoCerts.getCertificateList())
				certs.add((X509Certificate) certificateFactory.generateCertificate(bytes.newInput()));
			CertPath path = certificateFactory.generateCertPath(certs);

			// Retrieves the most-trusted CAs from keystore.
			PKIXParameters params = new PKIXParameters(X509.trustedCaStore());
			// Revocation not supported in the current version.
			params.setRevocationEnabled(false);

			// Now verify the certificate chain is correct and trusted. This let's us get an identity linked pubkey.
			CertPathValidator validator = CertPathValidator.getInstance("PKIX");
			PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(path, params);
			PublicKey publicKey = result.getPublicKey();
			// OK, we got an identity, now check it was used to sign this message.
			Signature signature = Signature.getInstance(algorithm);
			// Note that we don't use signature.initVerify(certs.get(0)) here despite it being the most obvious
			// way to set it up, because we don't care about the constraints specified on the certificates: any
			// cert that links a key to a domain name or other identity will do for us.
			signature.initVerify(publicKey);
			Protos.PaymentRequest.Builder reqToCheck = paymentRequest.toBuilder();
			reqToCheck.setSignature(ByteString.EMPTY);
			signature.update(reqToCheck.build().toByteArray());
			if (!signature.verify(paymentRequest.getSignature().toByteArray()))
				throw new PaymentRequestException.PkiVerificationException("Invalid signature, this payment request is not valid.");

			// Signature verifies, get the names from the identity we just verified for presentation to the user.
			final X509Certificate subjectCert = certs.get(0);
			final Collection<List<?>> subjectAlternativeNames = subjectCert.getSubjectAlternativeNames();
			String altName = null;
			if (subjectAlternativeNames != null)
				for (final List<?> subjectAlternativeName : subjectAlternativeNames)
					if ((Integer) subjectAlternativeName.get(0) == 1) // rfc822name
						altName = (String) subjectAlternativeName.get(1);
			X500Principal principal = subjectCert.getSubjectX500Principal();
			// At this point the Java crypto API falls flat on its face and dies - there's no clean way to get the
			// different parts of the certificate name except for parsing the string. That's hard because of various
			// custom escaping rules and the usual crap. So, use Bouncy Castle to re-parse the string into binary form
			// again and then look for the names we want. Fail!
			final X500Name name = new X500Name(principal.getName());
			String entityName = null, orgName = null;
			for (RDN rdn : name.getRDNs())
			{
				AttributeTypeAndValue pair = rdn.getFirst();
				if (pair.getType().equals(RFC4519Style.cn))
					entityName = ((ASN1String) pair.getValue()).getString();
				else if (pair.getType().equals(RFC4519Style.o))
					orgName = ((ASN1String) pair.getValue()).getString();
			}
			if (entityName == null && orgName == null && altName == null)
				throw new PaymentRequestException.PkiVerificationException("Invalid certificate, no CN or O fields and no alternative name");
			// Everything is peachy. Return some useful data to the caller.
			return new X509.PkiVerificationData(entityName, orgName, altName, publicKey, result.getTrustAnchor());
		}
		catch (InvalidProtocolBufferException e)
		{
			// Data structures are malformed.
			throw new PaymentRequestException.InvalidPkiData(e);
		}
		catch (CertificateException e)
		{
			// The X.509 certificate data didn't parse correctly.
			throw new PaymentRequestException.PkiVerificationException(e);
		}
		catch (CertPathValidatorException e)
		{
			// The certificate chain isn't known or trusted, probably, the server is using an SSL root we don't
			// know about and the user needs to upgrade to a new version of the software (or import a root cert).
			throw new PaymentRequestException.PkiVerificationException(e);
		}
		catch (InvalidKeyException e)
		{
			// Shouldn't happen if the certs verified correctly.
			throw new PaymentRequestException.PkiVerificationException(e);
		}
		catch (SignatureException e)
		{
			// Something went wrong during hashing (yes, despite the name, this does not mean the sig was invalid).
			throw new PaymentRequestException.PkiVerificationException(e);
		}
		catch (GeneralSecurityException e)
		{
			throw new RuntimeException(e);
		}
	}

	private static PaymentIntent.Output parseOutput(@Nonnull final Protos.Output output) throws PaymentRequestException.InvalidOutputs
	{
		try
		{
			final BigInteger amount = BigInteger.valueOf(output.getAmount());
			final Script script = new Script(output.getScript().toByteArray());
			return new PaymentIntent.Output(amount, script);
		}
		catch (final ScriptException x)
		{
			throw new PaymentRequestException.InvalidOutputs("unparseable script in output: " + output.toString());
		}
	}

	public static Protos.Payment createPaymentMessage(@Nonnull final Transaction transaction, @Nullable final Address refundAddress,
			@Nullable final BigInteger refundAmount, @Nullable final String memo, @Nullable final byte[] merchantData)
	{
		final Protos.Payment.Builder builder = Protos.Payment.newBuilder();

		builder.addTransactions(ByteString.copyFrom(transaction.unsafeBitcoinSerialize()));

		if (refundAddress != null)
		{
			if (refundAmount.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) > 0)
				throw new IllegalArgumentException("refund amount too big for protobuf: " + refundAmount);

			final Protos.Output.Builder refundOutput = Protos.Output.newBuilder();
			refundOutput.setAmount(refundAmount.longValue());
			refundOutput.setScript(ByteString.copyFrom(ScriptBuilder.createOutputScript(refundAddress).getProgram()));
			builder.addRefundTo(refundOutput);
		}

		if (memo != null)
			builder.setMemo(memo);

		if (merchantData != null)
			builder.setMerchantData(ByteString.copyFrom(merchantData));

		return builder.build();
	}

	public static List<Transaction> parsePaymentMessage(final Protos.Payment paymentMessage)
	{
		final List<Transaction> transactions = new ArrayList<Transaction>(paymentMessage.getTransactionsCount());

		for (final ByteString transaction : paymentMessage.getTransactionsList())
			transactions.add(new Transaction(Constants.NETWORK_PARAMETERS, transaction.toByteArray()));

		return transactions;
	}

	public static Protos.PaymentACK createPaymentAck(@Nonnull final Protos.Payment paymentMessage, @Nullable final String memo)
	{
		final Protos.PaymentACK.Builder builder = Protos.PaymentACK.newBuilder();

		builder.setPayment(paymentMessage);

		builder.setMemo(memo);

		return builder.build();
	}

	public static String parsePaymentAck(@Nonnull final Protos.PaymentACK paymentAck)
	{
		final String memo = paymentAck.hasMemo() ? paymentAck.getMemo() : null;

		return memo;
	}
}
