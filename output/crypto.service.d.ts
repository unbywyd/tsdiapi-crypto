type KeyFormat = 'pem' | 'base64' | 'cryptoKey';
export declare class CryptoService {
    private masterKey;
    /**
     * Инициализация CryptoService с мастер-ключом.
     * @param masterKey Мастер-ключ для шифрования других ключей.
     */
    constructor();
    setMasterKey(masterKey: string): void;
    /**
     * Создает мастер-ключ на основе нескольких строковых компонентов, используя хеширование.
     * @param components - Массив строковых частей для создания мастер-ключа.
     * @param hashAlgorithm - Алгоритм хеширования, используемый для создания мастер-ключа (по умолчанию 'sha256').
     * @returns Мастер-ключ в формате base64.
     * @throws Ошибка, если предоставлено меньше двух компонентов.
     */
    generateMasterKeyFromComponents(components: string[], hashAlgorithm?: string): string;
    /**
     * Хэширует пароль с использованием соли.
     * @param {string} password - Пароль пользователя.
     * @returns {string} - Хэшированный пароль в формате `salt:hash`.
     */
    hashPassword(password: string): string;
    /**
     * Проверяет пароль пользователя с хэшем из базы данных.
     * @param {string} password - Введенный пользователем пароль.
     * @param {string} storedHash - Хэш пароля из базы данных (в формате `salt:hash`).
     * @returns {boolean} - True, если пароли совпадают, иначе false.
     */
    verifyPassword(password: string, storedHash: string): boolean;
    isBase64KeyValid(base64Key: string): boolean;
    /**
     * Конвертирует PEM строку в ArrayBuffer.
     * @param pem PEM строка ключа.
     * @returns ArrayBuffer представление ключа.
     */
    private pemToArrayBuffer;
    /**
     * Конвертирует ArrayBuffer в PEM строку.
     * @param buffer ArrayBuffer данных ключа.
     * @param type Тип ключа ('public' или 'private').
     * @returns PEM строка ключа.
     */
    private arrayBufferToPem;
    /**
     * Конвертирует ArrayBuffer в Base64 строку.
     * @param buffer ArrayBuffer данных.
     * @returns Base64 строка.
     */
    private arrayBufferToBase64;
    /**
     * Конвертирует Base64 строку в ArrayBuffer.
     * @param base64 Base64 строка.
     * @returns ArrayBuffer данных.
     */
    private base64ToArrayBuffer;
    /**
     * Генерирует ключ для шифрования/дешифрования с использованием scrypt.
     * @param password Пароль для производного ключа.
     * @param salt Соль для scrypt.
     * @returns CryptoKey производного ключа.
     */
    private deriveEncryptionKey;
    /**
     * Генерация пары RSA-ключей для подписей (RSA-PSS).
     * @param format Формат возвращаемых ключей ('pem', 'base64', 'cryptoKey').
     * @returns Публичный и приватный ключи в указанном формате.
     */
    generateSigningKeyPair(format?: KeyFormat): Promise<{
        publicKey: string | CryptoKey;
        privateKey: string | CryptoKey;
    }>;
    /**
     * Генерация пары RSA-ключей для шифрования (RSA-OAEP).
     * @param format Формат возвращаемых ключей ('pem', 'base64', 'cryptoKey').
     * @returns Публичный и приватный ключи в указанном формате.
     */
    generateEncryptionKeyPair(format?: KeyFormat): Promise<{
        publicKey: string | CryptoKey;
        privateKey: string | CryptoKey;
    }>;
    /**
     * Генерация симметричного AES-ключа.
     * @param format Формат возвращаемого ключа ('base64', 'cryptoKey').
     * @returns Симметричный ключ в указанном формате.
     */
    generateSymmetricKey(format?: 'base64' | 'cryptoKey'): Promise<string | CryptoKey>;
    /**
     * Конвертация CryptoKey в PEM формат.
     * @param key CryptoKey для конвертации.
     * @param type Тип ключа ('public' или 'private').
     * @returns PEM строка ключа.
     */
    convertCryptoKeyToPem(key: CryptoKey, type: 'public' | 'private'): Promise<string>;
    /**
     * Конвертация PEM строки в CryptoKey.
     * @param pem PEM строка ключа.
     * @param type Тип ключа ('public' или 'private').
     * @param algorithm Параметры алгоритма импорта.
     * @param usages Разрешенные операции с ключом.
     * @returns CryptoKey объект.
     */
    convertPemToCryptoKey(pem: string, type: 'public' | 'private', algorithm: RsaHashedImportParams, usages: KeyUsage[]): Promise<CryptoKey>;
    /**
     * Конвертация CryptoKey в Base64 строку.
     * @param key CryptoKey для конвертации.
     * @param format Формат экспорта ('spki' для публичных, 'pkcs8' для приватных, 'raw' для симметричных).
     * @returns Base64 строка ключа.
     */
    convertCryptoKeyToBase64(key: CryptoKey, format: 'spki' | 'pkcs8' | 'raw'): Promise<string>;
    /**
     * Конвертация Base64 строки в CryptoKey.
     * @param base64Key Base64 строка ключа.
     * @param format Формат ключа ('spki' для публичных, 'pkcs8' для приватных, 'raw' для симметричных).
     * @param algorithm Параметры алгоритма импорта.
     * @param usages Разрешенные операции с ключом.
     * @returns CryptoKey объект.
     */
    convertBase64ToCryptoKey(base64Key: string, format: 'spki' | 'pkcs8' | 'raw', algorithm: any, usages: KeyUsage[]): Promise<CryptoKey>;
    /**
     * Шифрует строку с использованием мастер-ключа (AES-GCM).
     * @param data Строка (хеш) для шифрования.
     * @returns Зашифрованная строка в формате Base64, включая соль и IV.
     */
    encryptStringWithMasterKey(data: string): Promise<string>;
    /**
         * Шифрует CryptoKey с использованием мастер-ключа (AES-GCM).
         * Поддерживает симметричные ключи (AES-GCM), приватные ключи (RSA-PSS/RSA-OAEP) и публичные ключи (RSA-PSS/RSA-OAEP).
         * @param key CryptoKey для шифрования.
         * @param keyType Тип ключа: 'symmetric' | 'private' | 'public'.
         * @returns Зашифрованный ключ в Base64 формате, включая соль и IV.
         */
    encryptKeyWithMasterKey(key: CryptoKey, keyType: 'symmetric' | 'private' | 'public'): Promise<string>;
    /**
   * Дешифрует симметричный ключ, зашифрованный публичным ключом, с использованием приватного ключа.
   * @param encryptedSymmetricKey Зашифрованный симметричный ключ в формате Base64.
   * @param privateKey Приватный ключ для дешифрования.
   * @returns Дешифрованный симметричный ключ в формате CryptoKey.
   */
    decryptSymmetricKeyWithPrivateKey(encryptedSymmetricKey: string, privateKey: CryptoKey): Promise<CryptoKey>;
    /**
     * Дешифрует строку, зашифрованную мастер-ключом (AES-GCM).
     * @param encryptedData Зашифрованная строка в формате Base64, включая соль и IV.
     * @returns Дешифрованная строка.
     */
    decryptStringWithMasterKey(encryptedData: string): Promise<string>;
    /**
     * Дешифрует ключ, зашифрованный мастер-ключом (AES-GCM).
     * Поддерживает дешифровку асимметричных ключей для шифрования и подписи, а также симметричных ключей.
     * @param encryptedKey Зашифрованный ключ в формате Base64, включая salt и IV.
     * @param keyPurpose Назначение ключа: 'encryption' | 'signing' | 'symmetric'.
     * @returns Дешифрованный ключ в формате CryptoKey.
     */
    decryptKeyWithMasterKey(encryptedKey: string, keyPurpose: 'encryption' | 'signing' | 'symmetric'): Promise<CryptoKey>;
    /**
     * Шифрование данных публичным ключом (RSA-OAEP).
     * @param data Данные для шифрования.
     * @param publicKey Публичный ключ для шифрования.
     * @returns Зашифрованные данные.
     */
    encryptWithPublicKey(data: Uint8Array, publicKey: CryptoKey): Promise<ArrayBuffer>;
    /**
     * Дешифрование данных приватным ключом (RSA-OAEP).
     * @param encryptedData Зашифрованные данные.
     * @param privateKey Приватный ключ для дешифрования.
     * @returns Дешифрованные данные.
     */
    decryptWithPrivateKey(encryptedData: ArrayBuffer, privateKey: CryptoKey): Promise<Uint8Array>;
    /**
     * Подпись данных приватным ключом (RSA-PSS).
     * @param data Данные для подписи (в виде строки или Uint8Array).
     * @param privateKey Приватный ключ для подписи.
     * @param outputFormat Формат возвращаемой подписи: "base64" или "ArrayBuffer".
     * @returns Подпись в формате Base64 или ArrayBuffer.
     */
    signData(data: string | Uint8Array, privateKey: CryptoKey, outputFormat?: 'base64' | 'ArrayBuffer'): Promise<string | ArrayBuffer>;
    /**
     * Проверка подписи данных публичным ключом (RSA-PSS).
     * @param data Данные, которые были подписаны (строка или Uint8Array).
     * @param signature Подпись для проверки (строка Base64 или ArrayBuffer).
     * @param publicKey Публичный ключ для проверки подписи.
     * @returns Результат проверки (true или false).
     */
    verifySignature(data: string | Uint8Array, signature: string | ArrayBuffer, publicKey: CryptoKey): Promise<boolean>;
    /**
    * Шифрует симметричный ключ с использованием публичного ключа.
    * @param symmetricKey Симметричный ключ для шифрования.
    * @param publicKey Публичный ключ для шифрования.
    * @returns Зашифрованный симметричный ключ в формате Base64.
    */
    encryptSymmetricKeyWithPublicKey(symmetricKey: CryptoKey, publicKey: CryptoKey): Promise<string>;
    /**
     * Шифрование симметричного ключа другим симметричным ключом (AES-GCM).
     * @param keyToEncrypt Симметричный ключ для шифрования.
     * @param encryptingKey Симметричный ключ для шифрования.
     * @returns Зашифрованный симметричный ключ в Base64 формате, включая IV.
     */
    encryptSymmetricKeyWithSymmetricKey(keyToEncrypt: CryptoKey, encryptingKey: CryptoKey): Promise<string>;
    /**
     * Дешифрование симметричного ключа другим симметричным ключом (AES-GCM).
     * @param encryptedKey Зашифрованный симметричный ключ в Base64 формате, включая IV.
     * @param decryptingKey Симметричный ключ для дешифрования.
     * @returns Дешифрованный симметричный ключ.
     */
    decryptSymmetricKeyWithSymmetricKey(encryptedKey: string, decryptingKey: CryptoKey): Promise<CryptoKey>;
    /**
     * Шифрование приватного ключа (для подписей или шифрования) симметричным ключом (AES-GCM).
     * @param privateKey Приватный CryptoKey для шифрования.
     * @param symmetricKey Симметричный ключ для шифрования.
     * @param keyPurpose Назначение ключа ('signing' или 'encryption').
     * @returns Зашифрованный приватный ключ в Base64 формате, включая IV.
     */
    encryptPrivateKeyWithSymmetricKey(privateKey: CryptoKey, symmetricKey: CryptoKey, keyPurpose: 'signing' | 'encryption'): Promise<string>;
    /**
     * Дешифрование приватного ключа (для подписей или шифрования) симметричным ключом (AES-GCM).
     * @param encryptedPrivateKey Зашифрованный приватный ключ в Base64 формате, включая IV.
     * @param symmetricKey Симметричный ключ для дешифрования.
     * @param keyPurpose Назначение ключа ('signing' или 'encryption').
     * @returns Дешифрованный CryptoKey.
     */
    decryptPrivateKeyWithSymmetricKey(encryptedPrivateKey: string, symmetricKey: CryptoKey, keyPurpose: 'signing' | 'encryption'): Promise<CryptoKey>;
    /**
     * Генерация мастер-ключа для шифрования других ключей (AES-GCM).
     * @returns Мастер-ключ в формате CryptoKey.
     */
    generateMasterKey(): Promise<CryptoKey>;
    /**
     * Шифрование данных симметричным ключом (AES-GCM).
     * @param data Данные для шифрования.
     * @param symmetricKey Симметричный ключ для шифрования.
     * @returns Зашифрованные данные в Base64 формате, включая IV.
     */
    encryptDataWithSymmetricKey(data: string | Uint8Array, symmetricKey: CryptoKey): Promise<string>;
    /**
     * Дешифрование данных симметричным ключом (AES-GCM).
     * @param encryptedData Зашифрованные данные в Base64 формате, включая IV.
     * @param symmetricKey Симметричный ключ для дешифрования.
     * @param outputFormat Формат возвращаемых данных: "string" или "Uint8Array".
     * @returns Дешифрованные данные в указанном формате.
     */
    decryptDataWithSymmetricKey(encryptedData: string, symmetricKey: CryptoKey, outputFormat?: 'string' | 'Uint8Array'): Promise<string | Uint8Array>;
}
export default CryptoService;
//# sourceMappingURL=crypto.service.d.ts.map