const crypto = require('crypto')
const fs = require('fs')
const util = require('util')

const cipherData = fs.readFileSync(`${__dirname}/key.json`)
const { key, algorithm } = JSON.parse(cipherData)

function encrypt(string) {
    const iv = crypto.randomBytes(8).toString('hex')
    const cipher = crypto.createCipheriv(algorithm, key, iv)

    let encrypted = cipher.update(string, 'utf8', 'hex')
    encrypted += cipher.final('hex')

    return `${encrypted}:${iv}`
}

function decrypt(string) {
    const [ encryptedStr, iv ] = string.split(':')
    const decipher = crypto.createDecipheriv(algorithm, key, iv)

    let decrypted = decipher.update(encryptedStr, 'hex', 'utf8')
    decrypted += decipher.final('utf8')

    return decrypted
}

const str = 'Привет! Как дела? тадададааддадад'

console.log(encrypt(str))
console.log(decrypt(encrypt(str)))

//-------------Hash--------------
const strForHash = 'how are u doing human?'
// const hash = crypto.createHash('sha512').update(strForHash).digest('hex')

async function scryptHash(string, salt) {
    const saltInUse = salt || crypto.randomBytes(16).toString('hex')

    const hashBuffer = await util.promisify(crypto.scrypt)(string, saltInUse, 32)

    return `${hashBuffer.toString('hex')}:${saltInUse}`
}

scryptHash(strForHash).then(hash => console.log(hash))

async function scryptVerify(string, hashAndSalt) {
    const [, salt] = hashAndSalt.split(':')
    return await scryptHash(string, salt) === hashAndSalt
}

scryptVerify(strForHash, 'c364eabf1d2e1bb7869ad3bf0a37c2adcc9a619301b5a9c2fdb5d9e045a72f97:57883c4ef5533e07bd8aef8eebb6f300')
 .then(isValid => console.log(isValid))