<?php
class FredJWT {
    public $secret;
    public $exp;

    public function __construct($secret, $exp) {
        $this->secret = $secret;
        $this->exp = $exp;
    }

    public function create_token($data) {
        $data["FredJWT_crt"] = time()-1;
        $data["FredJWT_exp"] = time()+$this->exp;

        $header = json_encode([
            'typ' => 'FredJWT',
            'alg' => 'sha256'
        ]);
        $payload = json_encode($data);
        $base64Header = base64_encode($header);
        $base64Payload = base64_encode($payload);
        $signature = hash_hmac('sha256', $base64Header . "." . $base64Payload, $this->secret, true);
        $base64Signature = base64_encode($signature);
        return base64_encode($base64Header . "." . $base64Payload . "." . $base64Signature);
    }

    public function verify_token($token) {
        $token = base64_decode($token);
        $tokenParts = explode('.', $token);
        $header = base64_decode($tokenParts[0]);
        $payload = base64_decode($tokenParts[1]);
        $signatureProvided = $tokenParts[2];

        $base64UrlHeader = base64_encode($header);
        $base64UrlPayload = base64_encode($payload);
        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $this->secret, true);
        $base64UrlSignature = base64_encode($signature);

        $response = [];
        if ($signatureProvided == $base64UrlSignature ) {
            $data = json_decode(base64_decode($base64UrlPayload), true);
            $now = time();
            if ($now > $data["FredJWT_crt"] and $now < $data["FredJWT_exp"]) {
            $response["valid"] = true;
            $response["expiry_date"] = date("Y-m-d H:i:s", $data["FredJWT_exp"]);
            
            unset($data["FredJWT_crt"]);
            unset($data["FredJWT_exp"]);
            $response["data"] = $data;
            } else {
                $response["valid"] = false;
                $response["message"] = "Token expired";
            }
        } else {
            $response["valid"] = false;
            $response["message"] = "Invalid signature";
        }
        return $response;
    }
}
?>
