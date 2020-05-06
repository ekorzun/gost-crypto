import ab2str from 'arraybuffer-to-string'
import str2ab from 'string-to-arraybuffer'

const gost = require('./src/index')
console.log(gost)

window.gost = gost


gost.subtle.digest('GOST R 34.11', str2ab('Test message'))
  .then(buf => {
    console.log(ab2str(buf, 'hex'))
  })
  .catch(err => {
    console.error(err)
  })


// gost.subtle.generateKey('GOST R 34.10', true, ['sign', 'verify']).then(function (keyPair) {

//   // Store key in secluded place
//   return gost.subtle.exportKey('raw', keyPair.privateKey).then(function (result) {

//     console.log('gost.coding.Hex.encode(result): ', gost.coding.Hex.encode(result))

//     // Provide the public key to recepient
//     return gost.subtle.exportKey('raw', keyPair.publicKey).then(function (result) {
//       console.log('gost.coding.Hex.encode(result): ', gost.coding.Hex.encode(result))
//     })


//   })
// }).catch(function (error) {
//   console.log('error: ', error)
//   console.log('error: ', error.stack)
// })