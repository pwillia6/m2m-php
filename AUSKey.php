<?php

class AUSKey
{

    private $xml = '';
    private $credentials = array();
    private $credential_index = 0;
    private $salt;
    private $password = '';

    public function __construct($xml, $password = '', $id = '')
    {
        $this->xml = $xml;
        $this->password = $password;
        $this->id = $id;

        try {
            $this->parseXml();
        } catch (Exception $ex) {
            throw $ex;
        }
    }

    public function getPassword()
    {
        return $this->password;
    }

    private function parseXml()
    {
        if (empty($this->xml)) {
            throw new Exception("AUSKey is empty.");
        }

        $xml_obj = simplexml_load_string($this->xml);
        if (empty($xml_obj)) {
            throw new Exception("AUSKey is invalid or empty.");
        } else if (empty($xml_obj->credentials)) {
            throw new Exception("No credentials found in AUSKey.");
        }

        $this->salt = (string)$xml_obj->salt;

        $this->credentials = $xml_obj->credentials;
    }

    public function getCredential()
    {
        foreach ($this->credentials->credential as $d => $cred) {
            foreach ($cred->attributes() as $name => $value) {
                if ($name=='id' && $value==$this->id) {
                    return $cred;
                }
            }
        }
        throw new Exception("This credential (" . $this->id. ") isn't found in the AUSKey.");
    }
}