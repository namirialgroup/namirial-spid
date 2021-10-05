package validation;

import org.apache.commons.compress.utils.IOUtils;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.XMLParserException;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class SamlResponseValidator {

    public static void main(String[] args) throws Exception {
        if(args.length != 1) {
            System.out.println("Please provide the path to the file containing the base64 saml response to validate.");
            System.exit(1);
        }
        String responseFilePath = args[0];
        DefaultBootstrap.bootstrap();

        Response response = readFileIntoResponse(responseFilePath);
        X509Certificate cert = getIdpSigningCert(response);

        BasicX509Credential credential = new BasicX509Credential();
        credential.setEntityCertificate(cert);
        credential.setPublicKey(cert.getPublicKey());

        SignatureValidator validator = new SignatureValidator(credential);
        try {
            validator.validate(response.getSignature());
            System.out.println("Signature validation passed. Response valid.");

        } catch (ValidationException e) {
            System.out.println("SignatureValidator failed validation. Cause: " + e.getCause());
            throw e;
        }
    }

    public static Response readFileIntoResponse(String responseFilePath) throws ParserConfigurationException, IOException, SAXException, UnmarshallingException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);

        //Read file as byte array and
        byte[] bytes = IOUtils.toByteArray(new FileInputStream(responseFilePath));
        //Decode the base64 response into a string
        String samlRespAsString = new String(Base64.getDecoder().decode(bytes));
        //Read in the response as a string to the DocumentBuilder
        Document doc = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(samlRespAsString)));
        Element element = doc.getDocumentElement();
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
        XMLObject responseXmlObj = unmarshaller.unmarshall(element);
        return (Response) responseXmlObj;
    }

    public static java.security.cert.X509Certificate getIdpSigningCert(Response openSamlResponse) throws CertificateException {
        org.opensaml.xml.signature.X509Certificate cert = (org.opensaml.xml.signature.X509Certificate) openSamlResponse.getSignature()
                .getKeyInfo().getOrderedChildren().get(0).getOrderedChildren().get(0);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream is = new ByteArrayInputStream(org.opensaml.xml.util.Base64.decode(cert.getValue()));
        return (java.security.cert.X509Certificate) cf.generateCertificate(is);
    }
}