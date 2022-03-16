var crypto = require('crypto');
var NodeRSA = require('node-rsa');

function bin2hex (s) {
  var i
  var l
  var o = ''
  var n
  s += ''
  for (i = 0, l = s.length; i < l; i++) {
    n = s.charCodeAt(i)
      .toString(16)
    o += n.length < 2 ? '0' + n : n
  }
  return o
}

// Creez random 32 byte key
var aesKey = crypto.randomBytes(32).toString('hex').substr(0,32);

// iv este AUTHORIZATION INIT VECTOR de la PO
const iv = "";

// Initializez cipher AES 256 CBC folosind cheia AES generata de mine si IV furnizat de PO
var cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
cipher.setAutoPadding(true);
var po_auth_request = '<?xml version="1.0" encoding="UTF-8"?>\n\
<po_auth_request>\n\
  <f_sequence>714</f_sequence>\n\
  <f_login>demo website.ro</f_login>\n\
  <f_website>website.ro</f_website>\n\
  <f_test_request>1</f_test_request>\n\
  <f_timestamp>2021-10-27T08:25:42.780Z</f_timestamp>\n\
  <f_action>2</f_action>\n\
  <f_order_number>564654564</f_order_number>\n\
  <f_amount>1000</f_amount>\n\
  <f_currency>RON</f_currency>\n\
  <f_auth_minutes>10</f_auth_minutes>\n\
  <f_language>RO</f_language>\n\
  <customer_info>\n\
    <contact>\n\
      <f_email>email@domain.com</f_email>\n\
      <f_phone>0740000000</f_phone>\n\
      <f_first_name>Test</f_first_name>\n\
      <f_last_name>PO</f_last_name>\n\
      <f_middle_name/>\n\
    </contact>\n\
    <invoice>\n\
      <f_zip>800000</f_zip>\n\
      <f_country>RO</f_country>\n\
      <f_state>Bucuresti</f_state>\n\
      <f_city>Bucuresti</f_city>\n\
      <f_address>strada lunga nr .11</f_address>\n\
    </invoice>\n\
  </customer_info>\n\
  <shipping_info>\n\
    <same_info_as>1</same_info_as>\n\
  </shipping_info>\n\
  <card_holder_info>\n\
    <same_info_as>1</same_info_as>\n\
  </card_holder_info>\n\
  <transaction_relay_response>\n\
    <f_relay_response_url>https://demo.website.ro/auth_response</f_relay_response_url>\n\
    <f_relay_method>PTOR</f_relay_method>\n\
    <f_relay_handshake>1</f_relay_handshake>\n\
    <f_post_declined>1</f_post_declined>\n\
  </transaction_relay_response>\n\
  <f_order_string>1</f_order_string>\n\
  <f_order_cart>\n\
    <item>\n\
      <qty>1</qty>\n\
      <name>Produs de test 1</name>\n\
      <description>Produs de test 1</description>\n\
      <itemprice>1000</itemprice>\n\
      <vat>0</vat>\n\
      <stamp>2017-10-27</stamp>\n\
    </item>\n\
  </f_order_cart>\n\
</po_auth_request>';
// Criptez XML po_auth_request cu cipher si encode rezultatul cu base64
var aesEncryptedData = cipher.update(po_auth_request, 'utf8', 'base64');
aesEncryptedData += cipher.final('base64');


var f_message = bin2hex(aesEncryptedData);

// Initializez RSA key folosind AUTHORIZATION RSA PUBLIC KEY furnizat de PO
var key = new NodeRSA(`cheia publica de autorizare`);

// set encryption scheme to pkcs1
key.setOptions({encryptionScheme: 'pkcs1', environment: 'node'});

// encrypt AES KEY with RSA PUBKEY and encode base64
var f_crypt_message = key.encrypt(aesKey, 'base64');

console.log(f_message);
console.log(f_crypt_message);

// this is an encryption example, the validation against schema and the SOAP call to Plati.Online must be implemented by yourself
// you must generate po_auth_request XML based on your website order info, validate it against schema and send it via SOAP request to Plati.Online. You will obtain a redirect URL where your customer can pay
