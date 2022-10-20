# FredJWT - A simple PHP JWT Script

Usage
-----
```php
<?php
include_once dirname(__FILE__) . '/src/FredJWT.php';

// init
$FredJWT = new FredJWT('MySecretKey', 1000); //Set your secret and the expiration time (in seconds)

// Create Token
$userdata = [   //Add some data
  "username" => "Freddy",
  "user_id" => "1234"
];
$token = $FredJWT->create_token($userdata); //create a token with your data

// Verify token
$data = $FredJWT->verify_token($token); //You will get a repsonse with the data and information about the token
?>
```
