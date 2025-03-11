
import { subtle } from 'crypto';
import * as crypto from 'crypto';
import { Service } from 'typedi';

type KeyFormat = 'pem' | 'base64' | 'cryptoKey';

@Service()
export class CryptoService {
	private masterKey: string;

	/**
	 * Инициализация CryptoService с мастер-ключом.
	 * @param masterKey Мастер-ключ для шифрования других ключей.
	 */
	constructor() {
	}
	setMasterKey(masterKey: string) {
		this.masterKey = masterKey;
	}

	/**
	 * Создает мастер-ключ на основе нескольких строковых компонентов, используя хеширование.
	 * @param components - Массив строковых частей для создания мастер-ключа.
	 * @param hashAlgorithm - Алгоритм хеширования, используемый для создания мастер-ключа (по умолчанию 'sha256').
	 * @returns Мастер-ключ в формате base64.
	 * @throws Ошибка, если предоставлено меньше двух компонентов.
	 */
	public generateMasterKeyFromComponents(components: string[], hashAlgorithm: string = 'sha256'): string {
		if (components.length < 2) {
			throw new Error('Необходимо предоставить как минимум два компонента для создания мастер-ключа.');
		}

		// Объединяем все компоненты в один Buffer
		const combinedKeyBuffer = Buffer.concat(components.map((component) => Buffer.from(component)));

		// Создаем хеш объединенного Buffer и возвращаем его в формате base64
		return crypto.createHash(hashAlgorithm).update(combinedKeyBuffer).digest().toString('base64');
	}

	/**
	 * Хэширует пароль с использованием соли.
	 * @param {string} password - Пароль пользователя.
	 * @returns {string} - Хэшированный пароль в формате `salt:hash`.
	 */
	public hashPassword(password: string): string {
		const salt = crypto.randomBytes(16).toString('hex'); // Генерация соли
		const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex'); // Хэширование
		return `${salt}:${hash}`; // Сохранение соли и хэша вместе
	}

	/**
	 * Проверяет пароль пользователя с хэшем из базы данных.
	 * @param {string} password - Введенный пользователем пароль.
	 * @param {string} storedHash - Хэш пароля из базы данных (в формате `salt:hash`).
	 * @returns {boolean} - True, если пароли совпадают, иначе false.
	 */
	public verifyPassword(password: string, storedHash: string) {
		const [salt, hash] = storedHash.split(':'); // Разделение соли и хэша
		const hashToVerify = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex'); // Хэширование введенного пароля
		return hash === hashToVerify; // Сравнение хэшей
	}

	// ===========================
	// ========== HELPERS =========
	// ===========================

	public isBase64KeyValid(base64Key: string): boolean {
		try {
			const buffer = Buffer.from(base64Key, 'base64');
			return buffer.byteLength > 0;
		} catch (error) {
			return false;
		}
	}

	/**
	 * Конвертирует PEM строку в ArrayBuffer.
	 * @param pem PEM строка ключа.
	 * @returns ArrayBuffer представление ключа.
	 */
	private pemToArrayBuffer(pem: string): ArrayBuffer {
		const b64 = pem.replace(/-----BEGIN [A-Z ]+-----/, '')
			.replace(/-----END [A-Z ]+-----/, '')
			.replace(/\n/g, '');
		const binary = Buffer.from(b64, 'base64');
		return binary.buffer.slice(binary.byteOffset, binary.byteOffset + binary.byteLength);
	}

	/**
	 * Конвертирует ArrayBuffer в PEM строку.
	 * @param buffer ArrayBuffer данных ключа.
	 * @param type Тип ключа ('public' или 'private').
	 * @returns PEM строка ключа.
	 */
	private arrayBufferToPem(buffer: ArrayBuffer, type: 'public' | 'private'): string {
		const exportedAsBase64 = Buffer.from(buffer).toString('base64');
		let pemHeader: string;
		let pemFooter: string;

		if (type === 'private') {
			pemHeader = '-----BEGIN PRIVATE KEY-----';
			pemFooter = '-----END PRIVATE KEY-----';
		} else if (type === 'public') {
			pemHeader = '-----BEGIN PUBLIC KEY-----';
			pemFooter = '-----END PUBLIC KEY-----';
		} else {
			throw new Error("Unsupported key type. Use 'public' or 'private'.");
		}

		const pemBody = exportedAsBase64.match(/.{1,64}/g)?.join('\n') || exportedAsBase64;
		return `${pemHeader}\n${pemBody}\n${pemFooter}`;
	}

	/**
	 * Конвертирует ArrayBuffer в Base64 строку.
	 * @param buffer ArrayBuffer данных.
	 * @returns Base64 строка.
	 */
	private arrayBufferToBase64(buffer: ArrayBuffer): string {
		return Buffer.from(buffer).toString('base64');
	}

	/**
	 * Конвертирует Base64 строку в ArrayBuffer.
	 * @param base64 Base64 строка.
	 * @returns ArrayBuffer данных.
	 */
	private base64ToArrayBuffer(base64: string): ArrayBuffer {
		const binary = Buffer.from(base64, 'base64');
		return binary.buffer.slice(binary.byteOffset, binary.byteOffset + binary.byteLength);
	}

	/**
	 * Генерирует ключ для шифрования/дешифрования с использованием scrypt.
	 * @param password Пароль для производного ключа.
	 * @param salt Соль для scrypt.
	 * @returns CryptoKey производного ключа.
	 */
	private async deriveEncryptionKey(password: string, salt: Buffer): Promise<CryptoKey> {
		const derivedKey = await new Promise<Buffer>((resolve, reject) => {
			crypto.scrypt(password, salt, 32, (err, derivedKey) => {
				if (err) reject(err);
				else resolve(derivedKey as Buffer);
			});
		});

		return await subtle.importKey(
			'raw',
			derivedKey,
			{ name: 'AES-GCM' },
			false, // Не экспортируемый ключ
			['encrypt', 'decrypt']
		);
	}

	// ================================
	// ========== KEY GENERATION ======
	// ================================

	/**
	 * Генерация пары RSA-ключей для подписей (RSA-PSS).
	 * @param format Формат возвращаемых ключей ('pem', 'base64', 'cryptoKey').
	 * @returns Публичный и приватный ключи в указанном формате.
	 */
	async generateSigningKeyPair(format: KeyFormat = 'cryptoKey'): Promise<{ publicKey: string | CryptoKey; privateKey: string | CryptoKey }> {
		const keyPair = await subtle.generateKey(
			{
				name: 'RSA-PSS',
				modulusLength: 2048,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: 'SHA-256',
			},
			true, // Извлекаемый
			['sign', 'verify']
		);

		switch (format) {
			case 'cryptoKey':
				return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
			case 'pem':
				const publicKeyPem = this.arrayBufferToPem(await subtle.exportKey('spki', keyPair.publicKey), 'public');
				const privateKeyPem = this.arrayBufferToPem(await subtle.exportKey('pkcs8', keyPair.privateKey), 'private');
				return { publicKey: publicKeyPem, privateKey: privateKeyPem };
			case 'base64':
				const publicKeyBase64 = this.arrayBufferToBase64(await subtle.exportKey('spki', keyPair.publicKey));
				const privateKeyBase64 = this.arrayBufferToBase64(await subtle.exportKey('pkcs8', keyPair.privateKey));
				return { publicKey: publicKeyBase64, privateKey: privateKeyBase64 };
			default:
				throw new Error("Unsupported format. Use 'pem', 'base64' or 'cryptoKey'.");
		}
	}

	/**
	 * Генерация пары RSA-ключей для шифрования (RSA-OAEP).
	 * @param format Формат возвращаемых ключей ('pem', 'base64', 'cryptoKey').
	 * @returns Публичный и приватный ключи в указанном формате.
	 */
	async generateEncryptionKeyPair(format: KeyFormat = 'cryptoKey'): Promise<{ publicKey: string | CryptoKey; privateKey: string | CryptoKey }> {
		const keyPair = await subtle.generateKey(
			{
				name: 'RSA-OAEP',
				modulusLength: 2048,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: 'SHA-256',
			},
			true, // Извлекаемый
			['encrypt', 'decrypt']
		);

		switch (format) {
			case 'cryptoKey':
				return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
			case 'pem':
				const publicKeyPem = this.arrayBufferToPem(await subtle.exportKey('spki', keyPair.publicKey), 'public');
				const privateKeyPem = this.arrayBufferToPem(await subtle.exportKey('pkcs8', keyPair.privateKey), 'private');
				return { publicKey: publicKeyPem, privateKey: privateKeyPem };
			case 'base64':
				const publicKeyBase64 = this.arrayBufferToBase64(await subtle.exportKey('spki', keyPair.publicKey));
				const privateKeyBase64 = this.arrayBufferToBase64(await subtle.exportKey('pkcs8', keyPair.privateKey));
				return { publicKey: publicKeyBase64, privateKey: privateKeyBase64 };
			default:
				throw new Error("Unsupported format. Use 'pem', 'base64' or 'cryptoKey'.");
		}
	}

	/**
	 * Генерация симметричного AES-ключа.
	 * @param format Формат возвращаемого ключа ('base64', 'cryptoKey').
	 * @returns Симметричный ключ в указанном формате.
	 */
	async generateSymmetricKey(format: 'base64' | 'cryptoKey' = 'cryptoKey'): Promise<string | CryptoKey> {
		const key = await subtle.generateKey(
			{
				name: 'AES-GCM',
				length: 256,
			},
			true, // Извлекаемый
			['encrypt', 'decrypt']
		);

		switch (format) {
			case 'cryptoKey':
				return key;
			case 'base64':
				const rawKey = await subtle.exportKey('raw', key);
				return this.arrayBufferToBase64(rawKey);
			default:
				throw new Error("Unsupported format. Use 'base64' or 'cryptoKey'.");
		}
	}

	// ================================
	// ====== CONVERSION METHODS =======
	// ================================

	/**
	 * Конвертация CryptoKey в PEM формат.
	 * @param key CryptoKey для конвертации.
	 * @param type Тип ключа ('public' или 'private').
	 * @returns PEM строка ключа.
	 */
	async convertCryptoKeyToPem(key: CryptoKey, type: 'public' | 'private'): Promise<string> {
		const exportFormat = type === 'public' ? 'spki' : 'pkcs8';
		const exported = await subtle.exportKey(exportFormat, key);
		return this.arrayBufferToPem(exported, type);
	}

	/**
	 * Конвертация PEM строки в CryptoKey.
	 * @param pem PEM строка ключа.
	 * @param type Тип ключа ('public' или 'private').
	 * @param algorithm Параметры алгоритма импорта.
	 * @param usages Разрешенные операции с ключом.
	 * @returns CryptoKey объект.
	 */
	async convertPemToCryptoKey(pem: string, type: 'public' | 'private', algorithm: RsaHashedImportParams, usages: KeyUsage[]): Promise<CryptoKey> {
		const arrayBuffer = this.pemToArrayBuffer(pem);
		const format = type === 'public' ? 'spki' : 'pkcs8';
		return await subtle.importKey(
			format,
			arrayBuffer,
			algorithm,
			true,
			usages
		);
	}

	/**
	 * Конвертация CryptoKey в Base64 строку.
	 * @param key CryptoKey для конвертации.
	 * @param format Формат экспорта ('spki' для публичных, 'pkcs8' для приватных, 'raw' для симметричных).
	 * @returns Base64 строка ключа.
	 */
	async convertCryptoKeyToBase64(key: CryptoKey, format: 'spki' | 'pkcs8' | 'raw'): Promise<string> {
		const exported = await subtle.exportKey(format, key);
		return this.arrayBufferToBase64(exported);
	}

	/**
	 * Конвертация Base64 строки в CryptoKey.
	 * @param base64Key Base64 строка ключа.
	 * @param format Формат ключа ('spki' для публичных, 'pkcs8' для приватных, 'raw' для симметричных).
	 * @param algorithm Параметры алгоритма импорта.
	 * @param usages Разрешенные операции с ключом.
	 * @returns CryptoKey объект.
	 */
	async convertBase64ToCryptoKey(base64Key: string, format: 'spki' | 'pkcs8' | 'raw', algorithm: any, usages: KeyUsage[]): Promise<CryptoKey> {
		const arrayBuffer = this.base64ToArrayBuffer(base64Key);
		return await subtle.importKey(
			format,
			arrayBuffer,
			algorithm,
			true,
			usages
		);
	}


	// ================================
	// ===== ENCRYPTION METHODS =======
	// ================================

	/**
	 * Шифрует строку с использованием мастер-ключа (AES-GCM).
	 * @param data Строка (хеш) для шифрования.
	 * @returns Зашифрованная строка в формате Base64, включая соль и IV.
	 */
	async encryptStringWithMasterKey(data: string): Promise<string> {
		// Конвертируем строку в Uint8Array
		const dataArray = new TextEncoder().encode(data);

		// Генерируем случайную соль и IV
		const salt = crypto.randomBytes(16); // 128-битная соль
		const iv = crypto.randomBytes(12);   // 96-битный IV для AES-GCM

		// Вычисляем производный ключ на основе мастер-пароля и соли
		const derivedKey = await this.deriveEncryptionKey(this.masterKey, salt);

		// Шифруем данные с использованием AES-GCM
		const encryptedData = await subtle.encrypt(
			{ name: 'AES-GCM', iv },
			derivedKey,
			dataArray
		);

		// Объединяем salt + iv + encryptedData
		const combined = Buffer.concat([salt, iv, Buffer.from(encryptedData)]);
		return combined.toString('base64');
	}

	/**
		 * Шифрует CryptoKey с использованием мастер-ключа (AES-GCM).
		 * Поддерживает симметричные ключи (AES-GCM), приватные ключи (RSA-PSS/RSA-OAEP) и публичные ключи (RSA-PSS/RSA-OAEP).
		 * @param key CryptoKey для шифрования.
		 * @param keyType Тип ключа: 'symmetric' | 'private' | 'public'.
		 * @returns Зашифрованный ключ в Base64 формате, включая соль и IV.
		 */
	async encryptKeyWithMasterKey(
		key: CryptoKey,
		keyType: 'symmetric' | 'private' | 'public'
	): Promise<string> {
		let exportFormat: 'raw' | 'pkcs8' | 'spki';

		// Определяем формат экспорта на основе типа ключа
		switch (keyType) {
			case 'symmetric':
				exportFormat = 'raw';
				break;
			case 'private':
				exportFormat = 'pkcs8';
				break;
			case 'public':
				exportFormat = 'spki';
				break;
			default:
				throw new Error(`Unsupported key type: ${keyType}`);
		}

		// Экспортируем ключ в соответствующем формате
		const keyData = await subtle.exportKey(exportFormat, key);
		const keyBytes = new Uint8Array(keyData);

		// Генерируем случайную соль и IV для AES-GCM
		const salt = crypto.randomBytes(16); // 128-bit salt
		const iv = crypto.randomBytes(12);   // 96-bit IV

		// Генерируем производный ключ на основе мастер-пароля и соли
		const derivedKey = await this.deriveEncryptionKey(this.masterKey, salt);

		// Шифруем экспортированные данные с использованием производного ключа
		const encryptedData = await subtle.encrypt(
			{ name: 'AES-GCM', iv },
			derivedKey,
			keyBytes
		);

		// Объединяем salt, iv и зашифрованные данные
		const combined = Buffer.concat([salt, iv, Buffer.from(encryptedData)]);
		return combined.toString('base64');
	}

	/**
   * Дешифрует симметричный ключ, зашифрованный публичным ключом, с использованием приватного ключа.
   * @param encryptedSymmetricKey Зашифрованный симметричный ключ в формате Base64.
   * @param privateKey Приватный ключ для дешифрования.
   * @returns Дешифрованный симметричный ключ в формате CryptoKey.
   */
	async decryptSymmetricKeyWithPrivateKey(encryptedSymmetricKey: string, privateKey: CryptoKey): Promise<CryptoKey> {
		const encryptedKeyBuffer = Buffer.from(encryptedSymmetricKey, 'base64');

		// Дешифруем симметричный ключ с использованием приватного ключа и алгоритма RSA-OAEP
		const decryptedKeyBuffer = await subtle.decrypt(
			{
				name: 'RSA-OAEP',
			},
			privateKey,
			encryptedKeyBuffer
		);

		// Импортируем дешифрованный симметричный ключ обратно в CryptoKey
		return await subtle.importKey(
			'raw',
			decryptedKeyBuffer,
			{ name: 'AES-GCM', length: 256 },
			true,
			['encrypt', 'decrypt']
		);
	}

	/**
	 * Дешифрует строку, зашифрованную мастер-ключом (AES-GCM).
	 * @param encryptedData Зашифрованная строка в формате Base64, включая соль и IV.
	 * @returns Дешифрованная строка.
	 */
	async decryptStringWithMasterKey(encryptedData: string): Promise<string> {
		// Декодируем зашифрованные данные из Base64 в Buffer
		const combined = Buffer.from(encryptedData, 'base64');

		// Извлекаем соль, IV и зашифрованные данные
		const salt = combined.slice(0, 16); // Первые 16 байт — это соль
		const iv = combined.slice(16, 28);  // Следующие 12 байт — это IV
		const ciphertext = combined.slice(28); // Остальные байты — это зашифрованные данные

		// Вычисляем производный ключ на основе мастер-пароля и соли
		const derivedKey = await this.deriveEncryptionKey(this.masterKey, salt);

		// Дешифруем данные с использованием AES-GCM
		const decryptedData = await subtle.decrypt(
			{ name: 'AES-GCM', iv },
			derivedKey,
			ciphertext
		);

		// Конвертируем дешифрованные данные обратно в строку
		return new TextDecoder().decode(decryptedData);
	}


	/**
	 * Дешифрует ключ, зашифрованный мастер-ключом (AES-GCM).
	 * Поддерживает дешифровку асимметричных ключей для шифрования и подписи, а также симметричных ключей.
	 * @param encryptedKey Зашифрованный ключ в формате Base64, включая salt и IV.
	 * @param keyPurpose Назначение ключа: 'encryption' | 'signing' | 'symmetric'.
	 * @returns Дешифрованный ключ в формате CryptoKey.
	 */
	async decryptKeyWithMasterKey(encryptedKey: string, keyPurpose: 'encryption' | 'signing' | 'symmetric'): Promise<CryptoKey> {
		const combined = Buffer.from(encryptedKey, 'base64');
		const salt = combined.slice(0, 16); // 16 байт - это соль
		const iv = combined.slice(16, 28);  // Следующие 12 байт - это IV
		const encryptedData = combined.slice(28); // Остальные байты - это зашифрованный ключ

		// Генерация производного ключа на основе мастер-пароля и соли
		const derivedKey = await this.deriveEncryptionKey(this.masterKey, salt);

		// Дешифруем данные с использованием производного ключа
		const decryptedData = await subtle.decrypt(
			{ name: 'AES-GCM', iv },
			derivedKey,
			encryptedData
		);

		// Определение параметров для импорта ключа в зависимости от keyPurpose
		let algorithm: AlgorithmIdentifier | RsaHashedImportParams | AesKeyAlgorithm;
		let usages: KeyUsage[];

		if (keyPurpose === 'encryption') {
			algorithm = { name: 'RSA-OAEP', hash: 'SHA-256' };
			usages = ['decrypt'];
		} else if (keyPurpose === 'signing') {
			algorithm = { name: 'RSA-PSS', hash: 'SHA-256' };
			usages = ['sign'];
		} else if (keyPurpose === 'symmetric') {
			algorithm = { name: 'AES-GCM', length: 256 };
			usages = ['encrypt', 'decrypt'];
		} else {
			throw new Error("Unsupported key purpose. Use 'encryption', 'signing', or 'symmetric'.");
		}

		// Формат для импорта ключа
		const importFormat = keyPurpose === 'symmetric' ? 'raw' : 'pkcs8';

		// Импорт ключа в формате CryptoKey с правильными параметрами
		return await subtle.importKey(
			importFormat,
			decryptedData,
			algorithm,
			true,
			usages
		);
	}


	/**
	 * Шифрование данных публичным ключом (RSA-OAEP).
	 * @param data Данные для шифрования.
	 * @param publicKey Публичный ключ для шифрования.
	 * @returns Зашифрованные данные.
	 */
	async encryptWithPublicKey(data: Uint8Array, publicKey: CryptoKey): Promise<ArrayBuffer> {
		return await subtle.encrypt(
			{
				name: 'RSA-OAEP',
			},
			publicKey,
			data
		);
	}

	/**
	 * Дешифрование данных приватным ключом (RSA-OAEP).
	 * @param encryptedData Зашифрованные данные.
	 * @param privateKey Приватный ключ для дешифрования.
	 * @returns Дешифрованные данные.
	 */
	async decryptWithPrivateKey(encryptedData: ArrayBuffer, privateKey: CryptoKey): Promise<Uint8Array> {
		const decryptedData = await subtle.decrypt(
			{
				name: 'RSA-OAEP',
			},
			privateKey,
			encryptedData
		);
		return new Uint8Array(decryptedData);
	}

	// ================================
	// ====== SIGNATURE METHODS =======
	// ================================

	/**
	 * Подпись данных приватным ключом (RSA-PSS).
	 * @param data Данные для подписи (в виде строки или Uint8Array).
	 * @param privateKey Приватный ключ для подписи.
	 * @param outputFormat Формат возвращаемой подписи: "base64" или "ArrayBuffer".
	 * @returns Подпись в формате Base64 или ArrayBuffer.
	 */
	async signData(
		data: string | Uint8Array,
		privateKey: CryptoKey,
		outputFormat: 'base64' | 'ArrayBuffer' = 'ArrayBuffer'
	): Promise<string | ArrayBuffer> {
		// Конвертируем строку в Uint8Array, если данные представлены в виде строки
		const dataArray = typeof data === 'string' ? new TextEncoder().encode(data) : data;

		// Выполняем подпись данных
		const signature = await subtle.sign(
			{
				name: 'RSA-PSS',
				saltLength: 32,
			},
			privateKey,
			dataArray
		);

		// Возвращаем подпись в нужном формате
		if (outputFormat === 'base64') {
			return Buffer.from(signature).toString('base64');
		}

		return signature;
	}


	/**
	 * Проверка подписи данных публичным ключом (RSA-PSS).
	 * @param data Данные, которые были подписаны (строка или Uint8Array).
	 * @param signature Подпись для проверки (строка Base64 или ArrayBuffer).
	 * @param publicKey Публичный ключ для проверки подписи.
	 * @returns Результат проверки (true или false).
	 */
	async verifySignature(
		data: string | Uint8Array,
		signature: string | ArrayBuffer,
		publicKey: CryptoKey
	): Promise<boolean> {
		// Конвертируем данные в Uint8Array, если они представлены в виде строки
		const dataArray = typeof data === 'string' ? new TextEncoder().encode(data) : data;

		// Конвертируем подпись в ArrayBuffer, если она представлена в виде строки Base64
		const signatureArray = typeof signature === 'string'
			? Uint8Array.from(Buffer.from(signature, 'base64')).buffer
			: signature;

		return await subtle.verify(
			{
				name: 'RSA-PSS',
				saltLength: 32,
			},
			publicKey,
			signatureArray,
			dataArray
		);
	}


	// ================================
	// ===== SYMMETRIC KEY METHODS =====
	// ================================



	/**
	* Шифрует симметричный ключ с использованием публичного ключа.
	* @param symmetricKey Симметричный ключ для шифрования.
	* @param publicKey Публичный ключ для шифрования.
	* @returns Зашифрованный симметричный ключ в формате Base64.
	*/
	async encryptSymmetricKeyWithPublicKey(symmetricKey: CryptoKey, publicKey: CryptoKey): Promise<string> {
		// Экспортируем симметричный ключ в "raw" формате
		const rawSymmetricKey = await subtle.exportKey('raw', symmetricKey);

		// Шифруем симметричный ключ с использованием публичного ключа и алгоритма RSA-OAEP
		const encryptedKey = await subtle.encrypt(
			{
				name: 'RSA-OAEP',
			},
			publicKey,
			rawSymmetricKey
		);

		// Возвращаем зашифрованный симметричный ключ в формате Base64
		return Buffer.from(encryptedKey).toString('base64');
	}

	/**
	 * Шифрование симметричного ключа другим симметричным ключом (AES-GCM).
	 * @param keyToEncrypt Симметричный ключ для шифрования.
	 * @param encryptingKey Симметричный ключ для шифрования.
	 * @returns Зашифрованный симметричный ключ в Base64 формате, включая IV.
	 */
	async encryptSymmetricKeyWithSymmetricKey(keyToEncrypt: CryptoKey, encryptingKey: CryptoKey): Promise<string> {
		const rawKey = await subtle.exportKey('raw', keyToEncrypt);
		const keyBytes = new Uint8Array(rawKey);

		const iv = crypto.randomBytes(12); // 96-bit IV for AES-GCM

		const encryptedData = await subtle.encrypt(
			{ name: 'AES-GCM', iv },
			encryptingKey,
			keyBytes
		);

		// Combine IV + encryptedData
		const combined = Buffer.concat([iv, Buffer.from(encryptedData)]);
		return combined.toString('base64');
	}

	/**
	 * Дешифрование симметричного ключа другим симметричным ключом (AES-GCM).
	 * @param encryptedKey Зашифрованный симметричный ключ в Base64 формате, включая IV.
	 * @param decryptingKey Симметричный ключ для дешифрования.
	 * @returns Дешифрованный симметричный ключ.
	 */
	async decryptSymmetricKeyWithSymmetricKey(encryptedKey: string, decryptingKey: CryptoKey): Promise<CryptoKey> {
		const combined = Buffer.from(encryptedKey, 'base64');
		const iv = combined.slice(0, 12); // First 12 bytes
		const encryptedData = combined.slice(12); // Rest is encrypted key

		const decryptedData = await subtle.decrypt(
			{ name: 'AES-GCM', iv },
			decryptingKey,
			encryptedData
		);

		return await subtle.importKey(
			'raw',
			decryptedData,
			{ name: 'AES-GCM' },
			true,
			['encrypt', 'decrypt']
		);
	}

	// ================================
	// ======= PRIVATE KEY ENCRYPTION ======
	// ================================

	/**
	 * Шифрование приватного ключа (для подписей или шифрования) симметричным ключом (AES-GCM).
	 * @param privateKey Приватный CryptoKey для шифрования.
	 * @param symmetricKey Симметричный ключ для шифрования.
	 * @param keyPurpose Назначение ключа ('signing' или 'encryption').
	 * @returns Зашифрованный приватный ключ в Base64 формате, включая IV.
	 */
	async encryptPrivateKeyWithSymmetricKey(privateKey: CryptoKey, symmetricKey: CryptoKey, keyPurpose: 'signing' | 'encryption'): Promise<string> {
		const keyData = await subtle.exportKey('pkcs8', privateKey);
		const keyBytes = new Uint8Array(keyData);

		const iv = crypto.randomBytes(12); // 96-bit IV for AES-GCM

		const encryptedData = await subtle.encrypt(
			{ name: 'AES-GCM', iv },
			symmetricKey,
			keyBytes
		);

		// Combine IV + encryptedData
		const combined = Buffer.concat([iv, Buffer.from(encryptedData)]);
		return combined.toString('base64');
	}

	/**
	 * Дешифрование приватного ключа (для подписей или шифрования) симметричным ключом (AES-GCM).
	 * @param encryptedPrivateKey Зашифрованный приватный ключ в Base64 формате, включая IV.
	 * @param symmetricKey Симметричный ключ для дешифрования.
	 * @param keyPurpose Назначение ключа ('signing' или 'encryption').
	 * @returns Дешифрованный CryptoKey.
	 */
	async decryptPrivateKeyWithSymmetricKey(encryptedPrivateKey: string, symmetricKey: CryptoKey, keyPurpose: 'signing' | 'encryption'): Promise<CryptoKey> {
		const combined = Buffer.from(encryptedPrivateKey, 'base64');
		const iv = combined.slice(0, 12); // First 12 bytes
		const encryptedData = combined.slice(12); // Rest is encrypted key

		const decryptedData = await subtle.decrypt(
			{ name: 'AES-GCM', iv },
			symmetricKey,
			encryptedData
		);

		// Импорт ключа с правильными параметрами
		let algorithm: RsaHashedImportParams;
		let usages: KeyUsage[];

		if (keyPurpose === 'encryption') {
			algorithm = { name: 'RSA-OAEP', hash: 'SHA-256' };
			usages = ['decrypt'];
		} else if (keyPurpose === 'signing') {
			algorithm = { name: 'RSA-PSS', hash: 'SHA-256' };
			usages = ['sign'];
		} else {
			throw new Error("Unsupported key purpose. Use 'signing' or 'encryption'.");
		}

		return await subtle.importKey(
			'pkcs8',
			decryptedData,
			algorithm,
			true,
			usages
		);
	}

	// ================================
	// ======== MASTER KEY METHODS =====
	// ================================

	/**
	 * Генерация мастер-ключа для шифрования других ключей (AES-GCM).
	 * @returns Мастер-ключ в формате CryptoKey.
	 */
	async generateMasterKey(): Promise<CryptoKey> {
		return await subtle.generateKey(
			{
				name: 'AES-GCM',
				length: 256,
			},
			true, // Извлекаемый
			['encrypt', 'decrypt']
		);
	}

	// ================================
	// ====== DATA ENCRYPTION =========
	// ================================

	/**
	 * Шифрование данных симметричным ключом (AES-GCM).
	 * @param data Данные для шифрования.
	 * @param symmetricKey Симметричный ключ для шифрования.
	 * @returns Зашифрованные данные в Base64 формате, включая IV.
	 */
	async encryptDataWithSymmetricKey(data: string | Uint8Array, symmetricKey: CryptoKey): Promise<string> {
		// Если данные представлены в виде строки, конвертируем их в Uint8Array
		const dataArray = typeof data === 'string' ? new TextEncoder().encode(data) : data;

		const iv = crypto.randomBytes(12); // 96-bit IV for AES-GCM

		const encryptedData = await subtle.encrypt(
			{ name: 'AES-GCM', iv },
			symmetricKey,
			dataArray
		);

		// Combine IV + encryptedData
		const combined = Buffer.concat([iv, Buffer.from(encryptedData)]);
		return combined.toString('base64');
	}


	/**
	 * Дешифрование данных симметричным ключом (AES-GCM).
	 * @param encryptedData Зашифрованные данные в Base64 формате, включая IV.
	 * @param symmetricKey Симметричный ключ для дешифрования.
	 * @param outputFormat Формат возвращаемых данных: "string" или "Uint8Array".
	 * @returns Дешифрованные данные в указанном формате.
	 */
	async decryptDataWithSymmetricKey(
		encryptedData: string,
		symmetricKey: CryptoKey,
		outputFormat: 'string' | 'Uint8Array' = 'string'
	): Promise<string | Uint8Array> {
		const combined = Buffer.from(encryptedData, 'base64');
		const iv = combined.slice(0, 12); // Первые 12 байт - это IV
		const data = combined.slice(12);  // Остальные байты - зашифрованные данные

		const decryptedData = await subtle.decrypt(
			{ name: 'AES-GCM', iv },
			symmetricKey,
			data
		);

		// Проверка формата вывода: если 'string', то конвертируем в строку
		if (outputFormat === 'string') {
			return new TextDecoder().decode(decryptedData);
		}

		// По умолчанию возвращаем Uint8Array
		return new Uint8Array(decryptedData);
	}
}

export default CryptoService;
