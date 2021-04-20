<?php

class AUSKey
{

    private $xml = '';
    private $credentials = array();
    private $credential_index = 0;
    private $salt;
    private $password = '';

    public function __construct($xml, $password = '')
    {
        $this->xml = $xml;
        $this->password = $password;

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

    public function setCredential($idx = 0)
    {
        if (!isset($this->credentials->credential[$idx])) {
            throw new Exception("This credential (" . $idx . ") isn't found in the AUSKey.");
        }
        $this->credential_index = $idx;
    }

    public function getCredential()
    {
        if (!isset($this->credentials->credential[$this->credential_index])) {
            throw new Exception("This credential (" . $this->credential_index . ") isn't found in the AUSKey.");
        }
        return $this->credentials->credential[$this->credential_index];
    }
}