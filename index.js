var crypto = require('crypto');

function base64UrlEncode (str){
    str  = str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');;
    return str
}

function base64UrlDecode(str){

    var base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4){
        base64 += '=';
    }
    return base64;
}

let JWT = {  
    
    //------------------------------- data encode---------------------------//
    encode : function( data , secret , algo='HS256' ) {

        if(algo == 'HS512'){
            header ={ "alg": "HS512", "typ": "JWT" }
            sha_algo = 'sha512'
        }else{
            header ={ "alg": "HS256", "typ": "JWT" }
            sha_algo = 'sha256'
        }
        
        if(Object.keys(data).length >= 1 && secret.length > 5 ){
            try{
                base64_header  = Buffer.from(JSON.stringify(header)).toString('base64')
                base64_header  = base64UrlEncode(base64_header)
                
                base64_data  = Buffer.from(JSON.stringify(data)).toString('base64');
                base64_data  = base64UrlEncode(base64_data)
                
                payload = base64_header+"." +base64_data;
                
                signature = crypto.createHmac(sha_algo, secret ).update(payload).digest("base64");
                signature = base64UrlEncode(signature)
        
                return {
                    header_payload :payload,
                    signature : signature
                };
            }
            catch (err) {
                console.log(err)
                return false;
            } 
        }
        else{
            return false;
        }
        
    },


    //------------------------------- data decode---------------------------//
    decode : function( encodedata , secret) {
        
        let return_data ={
            data : false,
            error: false
        }
        
        if(encodedata.length > 24){
            
            
            try{
                data_array = encodedata.split("."); 
                payload  = data_array[0]+'.'+data_array[1];

                base64_data = base64UrlDecode(data_array[1]);
                data    = JSON.parse(Buffer.from(base64_data, 'base64').toString())

                base64_header = base64UrlDecode(data_array[0]);
                header  = JSON.parse(Buffer.from(base64_header, 'base64').toString())
                
                if(header.alg == 'HS512'){
                    sha_algo = 'sha512'
                }else{
                    sha_algo = 'sha256'
                }

            }
            catch (err) {
                return_data.error = 'invalid header or payload'
            } 
        
            if(return_data.error == false ){
                
                /*==================================================================
                --------- for general JWT , where there is an expiry time ----------
                ====================================================================*/
                if(data.exp){
                    jwt_unix_time_stamp = Date.now() / 1000 | 0 ;
                    
                    if(jwt_unix_time_stamp < data.exp ){                   

                        encoded_by_clientJWT= crypto.createHmac(sha_algo, secret ).update(payload).digest("base64");
                        encoded_by_clientJWT = base64UrlEncode(encoded_by_clientJWT)
                        if( data_array[2] == encoded_by_clientJWT ) {                   
                            return_data.data = data
                        }
                        else{
                            
                            return_data.error = "invalid JWT signature"
                        }
                    }
                    else{
                        return_data.error = "expired token"
                    }
                }
                
                /*==================================================================
                ----------- for special JWT , where no expiry time is set ----------
                ====================================================================*/
                else{
                    encoded_by_clientJWT= crypto.createHmac(sha_algo, secret ).update(payload).digest("base64");
                    encoded_by_clientJWT = base64UrlEncode(encoded_by_clientJWT)

                    if( data_array[2] == encoded_by_clientJWT ) {                   
                        return_data.data = data
                    }
                    else{
                        return_data.error = "invalid JWT signature"
                    }
                }
            }
        }
        return return_data
    },




    
};


module.exports = { JWT_ENCODE :JWT.encode , JWT_DECODE : JWT.decode};