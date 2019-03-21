//
//  ViewController.swift
//  TouchAuthDemo
//
//  Created by huan.chen on 2019/3/20.
//  Copyright © 2019 huan.chen. All rights reserved.
//

import UIKit
import Security
import LocalAuthentication

struct UserInfo {
    var name: String
    var authKey: String
}

struct AuthInfo {
    static let server = "www.test.com"
    static let userKey = "test.user.key"
}

class ViewController: UIViewController {
    
    let userInfo: UserInfo = UserInfo(name: "westone", authKey: "theAuthKey")
    @IBOutlet weak var authSwith: UISwitch!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
        if let _ = UserDefaults.standard.object(forKey: AuthInfo.userKey) {
            authSwith.isOn = true
        } else {
            authSwith.isOn = false
        }
    }
    
    @IBAction func onAuthSwitchChanged(_ sender: UISwitch) {
        if sender.isOn {
            saveUserInfoAuth()
        } else {
            deleteUserInfoAuth()
        }
    }
    
    @IBAction func onClickAuth(_ sender: Any) {
        if let userInfo = getUserInfo() {
            alertMessage(message: userInfo.name + userInfo.authKey + "登陆成功")
        } else {
            alertMessage(message: "登陆失败")
        }
    }
    
    //MARK: - Internal Method
    func alertMessage(message: String) {
        let alertController = UIAlertController(title: nil,
                                                message: message,
                                                preferredStyle: .alert)
        let cancelAction = UIAlertAction(title: "确定",
                                         style: .cancel,
                                         handler: nil)
        alertController.addAction(cancelAction)
        self.present(alertController,
                     animated: true,
                     completion: nil)
    }
    
    func openAuth(message: String,
                  successHandler: @escaping ()->(Void),
                  failHandler: @escaping (Error?)->(Void)) {
        let context = LAContext()
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: message) { (success, error) in
            if success {
                successHandler()
            } else {
                failHandler(error)
            }
        }
    }
    
    func saveUserInfoAuth() {
        openAuth(message: "请确定开启指纹登陆", successHandler: { [unowned self] in
            DispatchQueue.main.async {
                if self.saveUserInfo() {
                    self.authSwith.isOn = true;
                    self.alertMessage(message: "开启成功")
                } else {
                    self.authSwith.isOn = false;
                    self.alertMessage(message: "开启失败")
                }
            }
            }, failHandler: { [unowned self] (_) in
                self.authSwith.isOn = false;
                self.alertMessage(message: "指纹认证失败")
        })
    }
    
    func deleteUserInfoAuth() {
        openAuth(message: "请确定关闭指纹登陆", successHandler: { [unowned self] in
            DispatchQueue.main.async {
                if self.deleteUserInfo() {
                    self.authSwith.isOn = false;
                    self.alertMessage(message: "关闭成功")
                } else {
                    self.authSwith.isOn = true;
                    self.alertMessage(message: "关闭失败")
                }
            }
            }, failHandler: { [unowned self] (_) in
                self.authSwith.isOn = true;
                self.alertMessage(message: "指纹认证失败")
        })
    }
    
    func saveUserInfo() -> Bool {
        guard let authKeyData = userInfo.authKey.data(using: .utf8) else {
            return false
        }
        let access = SecAccessControlCreateWithFlags(nil,
                                                     kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                     .biometryAny,
                                                     nil)
        let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrAccessControl as String: access as Any,
                                    kSecAttrAccount as String: userInfo.name,
                                    kSecAttrServer as String: AuthInfo.server,
                                    kSecValueData as String: authKeyData];
        let status = SecItemAdd(query as CFDictionary, nil)
        UserDefaults.standard.set(userInfo.name, forKey: AuthInfo.userKey)
        guard
            status == errSecSuccess,
            UserDefaults.standard.synchronize() else {
            return false
        }
        return true
    }
    
    func getUserInfo() -> UserInfo? {
        let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrServer as String: AuthInfo.server,
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecReturnAttributes as String: true,
                                    kSecUseOperationPrompt as String: "使用指纹登陆",
                                    kSecReturnData as String: true]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            return nil
        }
        guard
            let existingItem = item as? [String : Any],
            let authKeyData = existingItem[kSecValueData as String] as? Data,
            let authKey = String(data: authKeyData, encoding: .utf8),
            let name = existingItem[kSecAttrAccount as String] as? String else {
                return nil
        }
        let savedUserInfo = UserInfo(name: name, authKey: authKey)
        return savedUserInfo
    }
    
    func deleteUserInfo() -> Bool {
        let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
                                    kSecAttrServer as String: AuthInfo.server,
                                    kSecUseOperationPrompt as String: "取消指纹登陆"]
        let status = SecItemDelete(query as CFDictionary)
        UserDefaults.standard.removeObject(forKey: AuthInfo.userKey)
        guard
            status == errSecSuccess else {
            return false
        }
        return true
    }
}

