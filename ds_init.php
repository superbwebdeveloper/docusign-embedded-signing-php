<?php
/*
 * DocuSign configuration settings
 * https://developers.docusign.com/
 * Test API Token is valid for 8 hours only
 * https://developers.docusign.com/oauth-token-generator
 */

require_once(__DIR__ . '/vendor/autoload.php');

use DocuSign\eSign\Model\RecipientViewRequest;
use DocuSign\eSign\Api\EnvelopesApi;
use DocuSign\eSign\Model\Signer;
use DocuSign\eSign\Model\TemplateRole;
use DocuSign\eSign\Model\EnvelopeDefinition;
use DocuSign\eSign\Configuration;
use DocuSign\eSign\Client\ApiClient;

class DocusignInit {
    /**
     * @return array [token, expires_in]
     */
    protected static function requestNewToken($refresh_token) {
       $config = new Configuration();
       $apiClient = new ApiClient($config);
       $token = $apiClient->generateRefreshToken('PROMOTED LIVE INTEGRATION KEY', 'SECRET KEY', $refresh_token);	
       return array($token[0]['access_token'],$token[0]['refresh_token'],time() + 86400 * 27);
    }

    /**
     * @return string
     * @throws Exception
     */
    protected static function getToken() {
        $tokenFile = __DIR__ . '/token.json';
        $access_token = null;
        if (file_exists($tokenFile)) {
            $data = json_decode(file_get_contents($tokenFile), true);
            $access_token = $data['access_token']; 
            $refresh_token = $data['refresh_token']; 
            $expires_in = $data['expires_in']; 
            if ($expires_in <= time()) {
                $access_token = null;
            }
        }
        if (!$access_token) {
            list($access_token,$refresh_newtoken,$expires_in) = self::requestNewToken($refresh_token);
            if (!$access_token || !$refresh_newtoken || !$expires_in) {
                throw new Exception('Could not request new token.');
            }
            file_put_contents($tokenFile, json_encode(array(
                'access_token' => $access_token, // todo consider field names
                'refresh_token' => $refresh_newtoken, // todo consider field names
                'expires_in' => $expires_in // todo consider field names
            )));
        }
        return $access_token;
    }

    /**
     * @param object $customer from $controller->customer
     * @param object $session from $controller->session
     * @return string URL
     * @throws Exception
     */
    public static function buildUrl($customer, $session) {
        $token = self::getToken(); // todo - use it
        $dsConfig = array(
            'ds_client_id' => isset($session->data['user_id']) ? $session->data['user_id'] : "1",
            // The app's DocuSign integration key's secret
            'ds_client_secret' => $token,
            'signer_email' => $customer->isLogged() ? $customer->getEmail() : 'user@example.com',
            'signer_name' => $customer->isLogged() ? $customer->getFirstName() . ' ' . $customer->getLastName() : 'John Doe',
            // return url
            'app_url' => HTTPS_SERVER . 'public/agreement-accept.html',
            'authorization_server' => 'https://www.docusign.net/restapi',
            // Secret for encrypting session cookie content
            'session_secret' => isset($session->data['token']) ? $session->data['token'] : md5(time()),
            // a user can be silently authenticated
            'allow_silent_authentication' => true,
            'accountId' => 'xxx',
            'templateId' => 'xxxx'
        );

        $templateRole = new TemplateRole(array(
            'email' => $dsConfig['signer_email'],
            'name' => $dsConfig['signer_name'],
            'role_name' => 'signer',
            'recipient_id' => '1',
            'routing_order' => '1',
            'client_user_id' => $dsConfig['ds_client_id']
        ));
        $envelopeDefinition = new EnvelopeDefinition(array(
            'status' => 'sent',
            'template_id' => $dsConfig['templateId']
        ));
        $envelopeDefinition->setTemplateRoles(array($templateRole));
        $config = new Configuration();
        $config->setHost($dsConfig['authorization_server']);
        $config->addDefaultHeader(
            "Authorization",
            "Bearer " . $dsConfig['ds_client_secret']
        );
        $apiClient = new ApiClient($config);
        $envelopeApi = new EnvelopesApi($apiClient);
		try {
            $envCreate = $envelopeApi->createEnvelope($dsConfig['accountId'], $envelopeDefinition);
        } catch (DocuSign\eSign\ApiException $e){
            $this->logger->error("Error connecting Docusign : " . $e->getResponseBody()->errorCode . " " . $e->getResponseBody()->message);
        }
        
        $envId = $envCreate->getEnvelopeId();
        $_SESSION['envelope_id']= $envId;
        $recipient_view_request = new RecipientViewRequest(array(
            'authentication_method' => 'email',
            'client_user_id' => $dsConfig['ds_client_id'],
            'recipient_id' => '1',
            'routing_order' => '1',
            'return_url' => $dsConfig['app_url'],
            'user_name' => $dsConfig['signer_name'],
            'email' => $dsConfig['signer_email']
        ));
        $signingView = $envelopeApi->createRecipientView($dsConfig['accountId'], $envId, $recipient_view_request);
        return $signingView->getUrl();
    }
}
