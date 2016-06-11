//
//  RetrieveISBN.swift
//  ClassLibrary
//
//  Created by Rob Myers on 6/2/16.
//  Copyright © 2016 Black Cloud Software. All rights reserved.
//

import Foundation

class RetrieveISBN {
    
    let accessKey : String! = "Your-Access-Key"
    let secretKey : String! = "Your-Secret-Key"
    let endPoint : String! = "webservices.amazon.com"
    
    //must use this format or it will not sign right
    let AWSDateISO8601DateFormat3 = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"

    let uri : String! = "/onca/xml"
    
    //Setup the parameters however you need for the products you want returned
    //Mine was specifically made to retrieve book information
    var params : Dictionary! = [
        "Service":"AWSECommerceService",
        "Operation":"ItemLookup",
        "AWSAccessKeyId":"Your-Access-Key",
        "AssociateTag":"Your-Associate-Tag",
        "ItemId":"",
        "IdType":"ISBN",
        "ResponseGroup":"Images,ItemAttributes",
        "SearchIndex":"Books"
    ]
    
    var finalURL: String! = ""
    
    //pass in the item your looking for as string value when you initialize
    init(bookIsbn: String){
        
        params["ItemId"] = bookIsbn
        
        params["Timestamp"] = FormatStringFromDate(NSDate()) as String
        
        var canonicalStringArray = [String]()
        
        // alphabetize
        let sortedKeys = Array(params.keys).sort {$0 < $1}
        
        for key in sortedKeys {
            canonicalStringArray.append("\(key)=\(params[key]!)")
        }
        
        let canonicalString = canonicalStringArray.joinWithSeparator("&")
        let escape = NSMutableCharacterSet.alphanumericCharacterSet()
        escape.removeCharactersInString(":,")
        escape.addCharactersInString("!*'();@&=+$/?%#[]-.")
        
        
        let encodedCanonicalString = canonicalString.stringByAddingPercentEncodingWithAllowedCharacters(escape)

        let stringToSign : String! = "GET\n" + endPoint + "\n" + uri + "\n" + encodedCanonicalString!
        
        //call the string extension to generate the signature
        let encodedSignatureData = stringToSign.hmacSHA256(secretKey)
        
        var encodedSignatureString = encodedSignatureData.base64EncodedString()
        
        let secondEscape = NSMutableCharacterSet.alphanumericCharacterSet()
        secondEscape.removeCharactersInString("+=")
        encodedSignatureString = encodedSignatureString.stringByAddingPercentEncodingWithAllowedCharacters(secondEscape)!
        
        //this is the final URL needed to access the product XML, return it or pass it where you need it
        finalURL = "http://\(endPoint)\(uri)?\(encodedCanonicalString!)&Signature=\(encodedSignatureString)"

    }
    
    private func FormatStringFromDate(date: NSDate) -> NSString {
        let dateFormatter = NSDateFormatter()
        dateFormatter.timeZone = NSTimeZone(name: "GMT")
        dateFormatter.dateFormat = AWSDateISO8601DateFormat3//"YYYY-MM-dd'T'HH:mm:ss'Z'"
        dateFormatter.locale = NSLocale(localeIdentifier: "en_US_POSIX")
        return dateFormatter.stringFromDate(date)
    }
    
}


public extension String {
    
        func hmacSHA256(key: String) -> NSData {
        let inputData: NSData = self.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)!
        let keyData: NSData = key.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)!
        let digestLen = Int(CC_SHA256_DIGEST_LENGTH)
        let result = UnsafeMutablePointer<CUnsignedChar>.alloc(digestLen)
        
        CCHmac(UInt32(kCCHmacAlgSHA256), keyData.bytes, Int(keyData.length), inputData.bytes, Int(inputData.length), result)
        let data = NSData(bytes: result, length: digestLen)
        return data
    }
    
}

public extension NSData {
    func base64EncodedString() -> String {
        return self.base64EncodedStringWithOptions([])
    }
}
