<?php

namespace app\index\controller;

use app\common\controller\Frontend;
use think\Db;
class App 
{
   
    public function list()
    {   
        $value = file_get_contents("php://input");
        $value = json_decode($value,true);
        $value = $value['value'];
        $openblack = Db::name('config')->where(['name'=>'openblack'])->value('value');
        $openblack2 = Db::name('config')->where(['name'=>'openblack2'])->value('value');

        if($value){
            $value = base64_decode($value);
            $udidArr = explode('|',$value);
            $udid1 = $udidArr[0];//添加者
            $udid2 = $udidArr[1];//破解者
            
            if($openblack == '1'){
                //自动拉黑
                if($udid1){
                    if(strlen($udid1) == '25' || strlen($udid1) == '40' ){
                        $res1 = Db::table('fa_black')->where(['udid'=>$udid1])->find();
                        if(!$res1){
                            Db::table('fa_black')->insert(['udid'=>$udid1,'addtime'=>time()]);
                        }
                        Db::table('fa_monitor')->where(['udid'=>$udid1])->delete();
                    }
                }
            }
            if($openblack2 == '1'){
                if($udid2){
                    if(strlen($udid2) == '25' || strlen($udid2) == '40' ){
                        $res2 = Db::table('fa_black')->where(['udid'=>$udid2])->find();
                        if(!$res2){
                            Db::table('fa_black')->insert(['udid'=>$udid2,'addtime'=>time()]);
                        }
                        Db::table('fa_monitor')->where(['udid'=>$udid2])->delete();
                    }
                }
            }
                //判断是否在黑明单;
                if($udid1 && $openblack != '1'){
                    if(strlen($udid1) == '25' || strlen($udid1) == '40' ){
                        $res1 = Db::name('black')->where('udid',$udid1)->find();
                        if(!$res1){
                            $r1 = Db::name('monitor')->where('udid',$udid1)->find();
                            if($r1){//增加次数
                                Db::name('monitor')->where('udid',$udid1)->inc('count',1)->update();
                            }else{
                                //添加记录
                                Db::name('monitor')->insert(['udid'=>$udid1,'identity'=>'添加者','count'=>1,'addtime'=>time()]);
                            }
                        }
                    }
                }
                if($udid2 && $openblack2 != '1'){
                    if(strlen($udid2) == '25' || strlen($udid2) == '40' ){
                    $res2 = Db::name('black')->where('udid',$udid2)->find();
                        if(!$res2){
                            $r2 = Db::name('monitor')->where('udid',$udid2)->find();
                            if($r2){//增加次数
                                Db::name('monitor')->where('udid',$udid2)->inc('count',1)->update();
                            }else{
                                //添加记录
                                Db::name('monitor')->insert(['udid'=>$udid2,'identity'=>'破解者','count'=>1,'addtime'=>time()]);
                            }
                        }
                    }
                }
            
        }
        
        $opencry = Db::name('config')->where(['name'=>'opencry'])->value('value');
		$udid = isset($_GET['udid'])?$_GET['udid']:'';
		if($udid == '') {$udid = '';}//return json(['code'=>0,'msg'=>'请上传参数UDID']);
		$kcode = isset($_GET['code'])?$_GET['code']:'';
		$nowtime = date("Y-m-d H:i:s");
		$black = Db::table('fa_black')->where('udid',$udid)->find();
		if($black){
            $json = [
              "name" => "已被源主拉黑",
              "message" => "你已被源主拉黑！",
              "identifier" => "长按此处删除软件源",
              "payURL" => "",
              "unlockURL" => "",
              "UDID" => $udid,
              "Time" => $nowtime,
              "apps" => [
                "0" => [
                  "name" => "你已被源主拉黑！",
                  "version" => "1.0",
                  "type" => "1.0",
                  "versionDate" => "2021-01-24",
                  "versionDescription" => "你已被源主拉黑！",
                  "lock" => "1",
                  "downloadURL" => "",
                  "isLanZouCloud" => "0",
                  "tintColor" => "",
                  "size" => "123973140.48"
                ]
              ]
            ];
            //请求接口
            if($opencry=='1'){//开启接口
                $content = json_encode($json,JSON_UNESCAPED_UNICODE);
                $content = base64_encode($content);
                $res = $this->rsa($content);
                $return["appstore_v1"] = $res;
                echo json_encode($return);die;
            }else{
                unset($json['UDID']);
                unset($json['Time']);
                echo json_encode($json,JSON_UNESCAPED_UNICODE);die;
            }
            
		}

		if($kcode == ''){
			$chkif = Db::table('fa_kami')->where('udid',$udid)->order('id desc')->select();
			if($chkif){
			    //var_dump('<pre>',$chkif);die;
				$ifend = time() > $chkif[0]['endtime']?true:false;
				$config = Db::table('fa_config')->select();
				if(empty($config)) return json(['code'=>0,'msg'=>'暂无站点数据']);
				$list = Db::table('fa_category')->where('status','normal')->order('weigh desc')->select();
				if(empty($list)) return json(['code'=>0,'msg'=>'暂无app数据']);
				$data = [];
				foreach ($list as $key=>$val)
				{
				    $lock = $val['bt2b'];
				    if($lock != '1'){
				        $downloadURL = $val['bt1a'];
				    }else{
				        if($ifend){
				            $downloadURL = '';
				        }else{
				            $downloadURL = $val['bt1a'];
				        }
				        
				    }
				    if($val['type'] == 'default'){
				        $val['type'] = 0;
				    }
					$data[$key]['name'] = $val['name'];
					$data[$key]['type'] = $val['type'];
					$data[$key]['version'] = $val['nickname'];
					$data[$key]['versionDate'] = date('Y-m-d\TH:i:s\+08:00',$val['updatetime']);
					$data[$key]['versionDescription'] = str_replace('\\n','@@@',$val['keywords']);
					$data[$key]['lock'] = $val['bt2b'];
					$data[$key]['downloadURL'] = $downloadURL;
					$data[$key]['isLanZouCloud'] = $val['flag'];
					$data[$key]['iconURL'] = $val['image'];
					$data[$key]['tintColor'] = $val['bt1b'];
					$data[$key]['size'] = $val['bt2a'];
				}
				foreach ($config as $key=>$val)
				{
					if($val['name'] == 'name') $info['name'] = $val['value'];
					if($val['name'] == 'message') $info['message'] = $val['value'];
					if($val['name'] == 'identifier') $info['identifier'] = $val['value'];
					if($val['name'] == 'sourceURL') $info['sourceURL'] = $val['value'];
					if($val['name'] == 'sourceicon') $info['sourceicon'] = $val['value'];
					if($val['name'] == 'payURL') $info['payURL'] = $val['value'];
					if($val['name'] == 'unlockURL') $info['unlockURL'] = $val['value'];
				}
				$arr = [
					'name'=>$info['name'],
					'message'=>$info['message'],
					'identifier'=>$info['identifier'],
					'sourceURL'=>$info['sourceURL'],
					'sourceicon'=>$info['sourceicon'],
					'payURL'=>$info['payURL'],
					'unlockURL'=>$info['unlockURL'],
					"UDID" => $udid,
                    "Time" => $nowtime,
					'apps'=>$data
					];
            
					if($opencry=='1'){//开启接口
                        $content = json_encode($arr,320);
                        $content = base64_encode($content);
                        $res = $this->rsa($content);
                        $return["appstore_v1"] = $res;
                        $json = json_encode($return);
                        $jsonStr  = str_replace('@@@', '\n', $json);
                        echo $jsonStr;die;
                    }else{
                        unset($arr['UDID']);
                        unset($arr['Time']);
                        $json = json_encode($arr,320);
                        $jsonStr  = str_replace('@@@', '\n', $json);
				        //$jsonStr  = str_replace('N', '\n', $json);
                        echo $jsonStr;die;
                    }
				$json = json_encode($arr,320);
				//halt($json);
				$jsonStr  = str_replace('N', '\n', $json);
				return $json;
			}else{
				$config = Db::table('fa_config')->select();
				if(empty($config)) return json(['code'=>0,'msg'=>'暂无站点数据']);
				$list = Db::table('fa_category')->where('status','normal')->order('weigh desc')->select();
				if(empty($list)) return json(['code'=>0,'msg'=>'暂无app数据']);
				$data = [];
				foreach ($list as $key=>$val)
				{
				    if($val['type'] == 'default'){
				        $val['type'] = 0;
				    }
					$data[$key]['name'] = $val['name'];
					$data[$key]['type'] = $val['type'];
					$data[$key]['version'] = $val['nickname'];
					$data[$key]['versionDate'] = date('Y-m-d\TH:i:s\+08:00',$val['updatetime']);
					$data[$key]['versionDescription'] = str_replace('\\n','@@@',$val['keywords']);
					$data[$key]['lock'] = $val['bt2b'];
					$data[$key]['downloadURL'] = $val['bt2b']?'':$val['bt1a'];
					$data[$key]['isLanZouCloud'] = $val['flag'];
					$data[$key]['iconURL'] = $val['image'];
					$data[$key]['tintColor'] = $val['bt1b'];
					$data[$key]['size'] = $val['bt2a'];
				}
				foreach ($config as $key=>$val)
				{
					if($val['name'] == 'name') $info['name'] = $val['value'];
					if($val['name'] == 'message') $info['message'] = $val['value'];
					if($val['name'] == 'identifier') $info['identifier'] = $val['value'];
					if($val['name'] == 'sourceURL') $info['sourceURL'] = $val['value'];
					if($val['name'] == 'sourceicon') $info['sourceicon'] = $val['value'];
					if($val['name'] == 'payURL') $info['payURL'] = $val['value'];
					if($val['name'] == 'unlockURL') $info['unlockURL'] = $val['value'];
				}
				$arr = [
					'name'=>$info['name'],
					'message'=>$info['message'],
					'identifier'=>$info['identifier'],
					'sourceURL'=>$info['sourceURL'],
					'sourceicon'=>$info['sourceicon'],
					'payURL'=>$info['payURL'],
					'unlockURL'=>$info['unlockURL'],
					"UDID" => $udid,
                    "Time" => $nowtime,
					'apps'=>$data
					];
					if($opencry=='1'){//开启接口
                        $content = json_encode($arr,320);
                        $content = base64_encode($content);
                        $res = $this->rsa($content);
                        $return["appstore_v1"] = $res;
                        $json = json_encode($return);
                        $jsonStr  = str_replace('@@@', '\n', $json);
                        echo $jsonStr;die;
                    }else{
                        unset($arr['UDID']);
                        unset($arr['Time']);
                        $json = json_encode($arr,320);
				        $jsonStr  = str_replace('@@@', '\n', $json);
                        echo $jsonStr;die;
                    }
				$json = json_encode($arr,320);
				//halt($json);
				$jsonStr  = str_replace('N', '\n', $json);
				return $json;
			}
		}else{
			$chkis = Db::table('fa_kami')->where('kami',$kcode)->order('id desc')->select();
			if($chkis){
				$kdata = $chkis[0];
				if(intval($kdata['jh'])){
					return json(['code'=>0,'msg'=>'解锁码已使用']);
				}else{
					//---
					$kmtp = intval($kdata['kmyp']);
					if($kmtp == 1){ $sydt = time(); $endtm = $sydt+(86400*30); }
					if($kmtp == 2){ $sydt = time(); $endtm = $sydt+(86400*30*3); }
					if($kmtp == 3){ $sydt = time(); $endtm = $sydt+(86400*30*12); }
					Db::table('fa_kami')->where('id', $kdata['id'])->update(array('udid'=>$udid, 'usetime'=>$sydt, 'endtime'=>$endtm, 'jh'=>1));
					return json(['code'=>0,'msg'=>'ok，解锁成功']);
				}
			}else{
				return json(['code'=>0,'msg'=>'解锁码不存在']);
			}
		}
    }
	public function rsa($content){
		$content = base64_decode($content);
		$content  = str_replace('@@@', '\n', $content);
		$result = new RSA();
		$enstr = $result->encrypt($content);
		return $enstr;
		
	}
    public function curl($url,$native){
		$postData = http_build_query($native);
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL,$url);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false); // stop verifying certificate
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_HTTPHEADER, array('Content-Type: application/x-www-form-urlencoded'));
        curl_setopt($curl, CURLOPT_POSTFIELDS, $postData);
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
        $data = curl_exec($curl);
        curl_close($curl);
        return $data;
    }
    public function log(){
        $value = $_REQUEST['value'];
    }
}
class RSA
{

        public $pri_key = '-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcw00SjAgEAAoIBAQClzR4c47lCuelb
oHQzqDoDHixxeryAbx0zFxLtxdmFJfm+ljOojcwsXDvX69UXA6UdCUzQDFQxVFU+
nTdQdq3P3OD8/OlrrBeeurdFl8R4k6FbZtpzk10S72SmyLsrIiOBM76uVFRRKkNm
dFVLvwCmiBrQVuj6eoJijkRQ8luBEPz3vRBSgIJ6Iim4h8RHZ18NoDZJP5KAPfC3
a2FQyEF2nmx6Bf5xscDj2OfgHx2XI2gl28wNY26y/iWKAymPwmO28WKbHiQMLN4y
kVGZnCOwOn8jAJWwUK2KPhAiTQF8DwOraLEFOYQctPovd8oa3rP+UZZfIr/h/5Rd
6ye7uFLpAgMBAAECggEAH7ZO1ym7SobymmLjNuorRmNkDsRx/4LBK/9y0GWySCRO
U2S5NrkAX0+45oCl/kPlNduMhJKHG/RMZbB+XvaEIijWI61gHAcLcYG3AimYG5Pp
HelbSRXbjH6bWscz/XkHH3Q9OWzJv8h8ocEIe3dp8XBA6K5m21nJTH53lJ/2XoYJ
Xi5UqBqBM0BLqJfxjD0DK1PuqWUtKcOHC/zpYFIEEzBsF0z169j/iQP9O0aJQEJg
pDidXTlNycy+e1krCJmOhXIdB1V1ErM/ny5D1FRtXUdm7hbvudmUqm8bgsQE6PyY
Ta1LuNFCMmUlRZApZtdz3Elq5V54+9lFn5WBabocDQKBgQDZsM6lDu/xltCUkk4X
4lac/NVG/tR3LJZRqh/8FhNTIBF4eRaYj6zlKMwrr+7UnxKegYUgi7mjmkx6LK2B
zkHd/iRc21Fzz5RsECcGnDp7dDWFdfD1OGpC7iMPSgIxaLFiBkCY4z62aOto91+G
yPgoCkqccg1bndHQFNKGjlIoDwKBgQDC+qNJahlpvg6t527prhDKZCLa7CZkmuVX
yURXlQdj6HYimABtE1y1nxSIFY/fnKPlLhsLNgtaVwi0p7OCwSSOUeCZJueJPw9h
ueS/eCh//LFr2ZXj43C6yhowAPaypXCZKgPlmrhEBMw1Z3JJlvP9sXavcs38fc6G
h6YOwuydhwKBgQC6dsAKkijk/xHasRdDThRyk/77uPu0uPRpLxgGjcIvyaAtWUsJ
kse94pxAL4qbhUYljzvBDO4OPPSVEf/s2AeDZ1UuVI4IbR3tEkjbWKafaIMPtl6X
LaOXgPN2/SWzvMFz/XcHfl8RT/2VA49HnI0zft059FeMyjoVykAqEW498QKBgD5Z
Ya/PQtMimJUZxcjqBaqCvPaev2Q6eA5LaRRMrrFPG7/SNYirwWC+vxUJOBm8gFiA
FtvN63F3FWyXl/q/Ao6UNisjWrTzulp41GI57VGIH8AqMxlNmLXSfO9Oz5Su/MOt
wNNCV5xAoICPVOedYuaEQjy2jJIqNMmmRP7BbGKvAoGAH+F3vw+KH4fpdEZ5pEK0
Io8MxpMvbRx6otaJfkj6yCtIi7aB+QEHBwd7rF6R+kxd8ZAvQGlzIqHpO0021LWP
qb0VC0hUA9IA5Cc5WG1YBPDItx2poe1Inlze1I9zz+s3UsCCPPRfd1B4m9ZOKixz
p8hiQeeGzKvkqXRuNq7e0IQ=
-----END PRIVATE KEY-----
';
    public $pub_key = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkW2mfZddF15yPY1ZCtcX
Y7A9IKxQusdxVQi4nhgsEsnbyuNqL6hkFpGbyOzy0aQyh3eWawZzQCqh1XmWxauD
UGPgg/+tEsxJvaZCOvDLOxqCGtQgmeMrgB2dL3cmXjNu9rG4Zi8G2OmIjkxbp6Er
iVpXLy7q0/REIwEBKoKqlmkl4LQujfKSVo7jY+Mgd1TPrQVCQVoDcDrdVldmOYsP
Kkt2wKLo0cmr0eLhVNwHFvV5cQGlUUM+qrF7Zbcf4V++ute9Owhk4Obvs+R9niHI
T1cBMlDmVoc4B4z+LEUOUp9UlKXl/6OYygcgLKZH8rkZhTZWKVHoDW0euVpVKqms
fwIDAQAB
-----END PUBLIC KEY-----';

    /**
     * RSA constructor.
     * @param null $publicKeyPath
     * @param null $privateKeyPath
     * @param null $publicKey
     * @param null $privateKey
     * @throws FileNotFoundException
     */
    public function __construct($publicKeyPath=null, $privateKeyPath=null, $publicKey=null, $privateKey=null) {

        if ($this->checkKeyFile($publicKeyPath)) {
            $this->pub_key = openssl_pkey_get_public(file_get_contents($publicKeyPath));
        }

        if ($this->checkKeyFile($privateKeyPath)) {
            $this->pri_key = openssl_pkey_get_private(file_get_contents($privateKeyPath));
        }
        if (!is_null($publicKey)) {
            $this->pub_key = openssl_pkey_get_public($this->formatterPublicKey($publicKey));
        }

        if (!is_null($privateKey)) {
            $this->pri_key = openssl_pkey_get_private($this->formatterPrivateKey($privateKey));
        }

    }

    /**
     * 校验文件是否存在
     * @param $keyPath string 文件路径
     * @return bool
     * @throws FileNotFoundException
     */
    public function checkKeyFile($keyPath)
    {
        if (!is_null($keyPath)) {
            if(!file_exists($keyPath)) {
                throw new FileNotFoundException($keyPath);
            }

            return true;
        }

        return false;
    }

    /**
     * 格式化公钥
     * @param $publicKey string 公钥
     * @return string
     */
    public function formatterPublicKey($publicKey)
    {
        if (str_contains('-----BEGIN PUBLIC KEY-----', $publicKey)) return $publicKey;

        $str = chunk_split($publicKey, 64, PHP_EOL);//在每一个64字符后加一个

        $publicKey = "-----BEGIN PUBLIC KEY-----".PHP_EOL.$str."-----END PUBLIC KEY-----";

        return $publicKey;
    }

    /**
     * 格式化私钥
     * @param $privateKey string 公钥
     * @return string
     */
    public function formatterPrivateKey($privateKey)
    {
        if (str_contains('-----BEGIN RSA PRIVATE KEY-----', $privateKey)) return $privateKey;

        $str = chunk_split($privateKey, 64, PHP_EOL);//在每一个64字符后加一个

        $privateKey = "-----BEGIN RSA PRIVATE KEY-----".PHP_EOL.$str."-----END RSA PRIVATE KEY-----";

        return $privateKey;
    }

    /**
     *  公钥加密（分段加密）
     *  emptyStr    需要加密字符串
     */
    public function encrypt($str) {
        $crypted = array();
        $data = $str;
        $dataArray = str_split($data, 245);
        foreach($dataArray as $subData){
            $subCrypted = null;
            openssl_public_encrypt($subData, $subCrypted, $this->pub_key);
            $crypted[] = $subCrypted;
        }
        $crypted = implode('',$crypted);
        return base64_encode($crypted);
    }

    /**
     *  私钥解密（分段解密）
     *  @encrypstr  加密字符串
     */
    public function decrypt($encryptstr) {
        $encryptstr = base64_decode($encryptstr);
        $decrypted = array();
        $dataArray = str_split($encryptstr, 256);
        foreach($dataArray as $subData){
            $subDecrypted = null;
            openssl_private_decrypt($subData, $subDecrypted, $this->pri_key);
            $decrypted[] = $subDecrypted;
        }
        $decrypted = implode('',$decrypted);
        return $decrypted;
    }

}