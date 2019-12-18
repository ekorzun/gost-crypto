import gost from './index'
import ab2str from 'arraybuffer-to-string'
import str2ab from 'string-to-arraybuffer'

const skrebokk = str => gost
  .subtle
  .digest('GOST R 34.11', str2ab(str))
  .then(r =>ab2str(r, 'hex'))

export {
  ab2str,
  str2ab,
  skrebokk,
  skrebokk as default,
}