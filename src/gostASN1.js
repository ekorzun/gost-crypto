/**
 * @file PKCS ASN.1 message syntax and converters
 * @version 1.76
 * @copyright 2014-2016, Rudolf Nickolaev. All rights reserved.
 */

/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


const gostCrypto = require('./gostCrypto')
// const GostCoding = require('./gostCoding')
// const GostSecurity = require('./gostSecurity')


const CryptoOperationData = global.ArrayBuffer

// Security parameters
const algorithms = gostCrypto.security.algorithms

const names = gostCrypto.security.names

const identifiers = gostCrypto.security.identifiers

const attributes = gostCrypto.security.attributes

const parameters = gostCrypto.security.parameters

// BER coding
const BER = gostCrypto.coding.BER

// PEM coding
const PEM = gostCrypto.coding.PEM

// Chars coding
const Chars = gostCrypto.coding.Chars

// Hex coding;
const Hex = gostCrypto.coding.Hex

// Hex coding;
const Int16 = gostCrypto.coding.Int16

// Expand javascript object
function expand() {
  const r = {}
  for (let i = 0, n = arguments.length; i < n; i++) {
    // eslint-disable-next-line
    const item = arguments[i]
    if (typeof item === 'object') {
      for (const name in item) {r[name] = item[name]}
    }
  }
  return r
}


// Swap bytes in buffer
function swapBytes(src) {
  if (src instanceof CryptoOperationData) {src = new Uint8Array(src)}
  const dst = new Uint8Array(src.length)
  for (let i = 0, n = src.length; i < n; i++) {dst[n - i - 1] = src[i]}
  return dst.buffer
}

function isBinary(value) {
  return value instanceof CryptoOperationData || value.buffer instanceof CryptoOperationData
}

// Left pad zero
function lpad(n, width) {
  return n.length >= width ? n : new Array(width - n.length + 1).join('0') + n
}

// Nearest power 2
function npw2(n) {
  return n <= 2 ? n : n <= 4 ? 4 : n <= 8 ? 8 : n <= 16 ? 16 :
    n <= 32 ? 32 : n <= 64 ? 64 : n <= 128 ? 128 : n <= 256 ? 256 :
      n < 512 ? 512 : n < 1024 ? 1024 : undefined
}

// String int encode/decode to buffer
const SInt = {
  encode: function (value, endian) {
    return `0x${ Hex.encode(value, endian)}`
  },
  decode: function (value, endian, len) {
    if (typeof value === 'number') {value = value.toString(16)}
    const s = value.replace('0x', '')
    len = len || npw2(s.length)
    return Hex.decode(lpad(s, len), endian)
  },
}

// Assert invalid message
function assert(value) {
  if (value) {throw Error('Invalid format')}
}

function defineProperty(object, name, descriptor, enumerable) {
  if (typeof descriptor !== 'object') {descriptor = { value: descriptor }}
  if (enumerable !== undefined) {descriptor.enumerable = enumerable}
  Object.defineProperty(object, name, descriptor)
}

function defineProperties(object, properties, enumerable) {
  for (const name in properties) {defineProperty(object, name, properties[name], enumerable)}
}

function getOwnPropertyDescriptor(object, name) {
  return Object.getOwnPropertyDescriptor(object, name)
}

// </editor-fold>

/*
 * Base ASN.1 types and definitions
 *
 */ // <editor-fold defaultstate="collapsed">

// Encode object primitive
function encode(format, object, tagNumber, tagClass, tagConstructed, uniformTitle) {
  assert(object === undefined)
  let source = {
    tagNumber: tagNumber,
    tagClass: tagClass || 0x00,
    tagConstructed: tagConstructed || false,
    object: object,
  }
  // Output format
  format = format || 'DER'
  if (format === 'DER' || format === 'CER') {source = BER.encode(source, format)}
  if (format === 'PEM') {source = PEM.encode(source, uniformTitle)}
  return source
}

// Decode object primitive
function decode(source, tagNumber, tagClass, tagConstructed, uniformTitle) {
  assert(source === undefined)

  // Decode PEM
  if (typeof source === 'string') {source = PEM.decode(source, uniformTitle, false)}
  // Decode binary data
  if (source instanceof CryptoOperationData) {
    try {
      source = PEM.decode(Chars.encode(source), uniformTitle, true)
    } catch (e) {
      source = BER.decode(source)
    }
  }

  tagClass = tagClass || 0
  tagConstructed = tagConstructed || false
  // Restore context implicit formats
  if (source.tagNumber === undefined) {
    source = encode(true, source.object, tagNumber, tagClass,
      source.object instanceof Array)
    source = BER.decode(source)
  }

  // Check format
  assert(source.tagClass !== tagClass ||
        source.tagNumber !== tagNumber ||
        source.tagConstructed !== tagConstructed)
  // Clone value define from redefine original
  if (tagClass === 0 && tagNumber === 0x05) {return null}
  return source.object
}

// Create class based on super
function extend(Super, Class, propertiesObject, propertiesClass) {
  // If constructor not defined
  if (typeof Class !== 'function') {
    propertiesClass = propertiesObject
    propertiesObject = Class
    Class = function () {
      Super.apply(this, arguments)
    }
  }
  // Create prototype properties
  Class.prototype = Object.create(Super.prototype, {
    constructor: {
      value: Class,
    },
    superclass: {
      value: Super.prototype,
    },
  })
  if (propertiesObject) {defineProperties(Class.prototype, propertiesObject)}
  // Inherites super class properties
  if (Super !== Object) {
    for (const name in Super) {Class[name] = Super[name]}
  }
  Class.super = Super
  if (propertiesClass) {defineProperties(Class, propertiesClass, true)}
  return Class
}

// Base class
const ASN1Object = extend(Object, function (object) {
  this.object = object
}, {
  // Call set method for a class property
  _set: function (Class, propName, value) {
    Class.property(propName).set.call(this, value)
  },
  // Call get method for a class property
  _get: function (Class, propName) {
    return Class.property(propName).get.call(this)
  },
  // Call method for a class
  _call: function (Class, methodName, args) {
    return Class.method(methodName).apply(this, args)
  },
  hasProperty: function (propName) {
    return this.hasOwnProperty(propName) ||
            !!this.constructor.property(propName)
  },
  encode: function () {
    return this.object
  },
}, {
  decode: function (source) {
    return new this(source)
  },
  // Find ingerited property
  property: function (propName) {
    let proto = this.prototype
    while (proto) {
      const descriptor = getOwnPropertyDescriptor(proto, propName)
      if (descriptor) {return descriptor}
      proto = proto.superclass
    }
  },
  // Find method
  method: function (methodName) {
    let proto = this.prototype
    while (proto) {
      if (proto[methodName]) {return proto[methodName]}
      proto = proto.superclass
    }
  },
})

// Primitive metaclass
const PRIMITIVE = function (tagNumber) {
  return extend(ASN1Object, {
    encode: function (format) {
      return encode(format, this.object, tagNumber)
    },
  }, {
    decode: function (source) {
      return new this(decode(source, tagNumber))
    },
  })
}

const ANY = ASN1Object

const BOOLEAN = PRIMITIVE(0x01)

const IA5String = PRIMITIVE(0x16)

const NumericString = PRIMITIVE(0x12)

const PrintableString = PRIMITIVE(0x13)

const TeletexString = PRIMITIVE(0x14)

const UTF8String = PRIMITIVE(0x0c)

const UTCTime = PRIMITIVE(0x17)

const GeneralizedTime = PRIMITIVE(0x18)

const UniversalString = PRIMITIVE(0x1C)

const BMPString = PRIMITIVE(0x1e)

const NULL = extend(PRIMITIVE(0x05), {
  object: {
    get: function () {
      return null
    },
    set: function (object) {
      assert(object !== null)
    },
  },
})

// Primitive class with value coding
const PRIMITIVE_CODE = function (tagNumber) {

  // Base class primitive
  const Class = extend(PRIMITIVE(tagNumber), function (object) {
    if (this instanceof Class) {Class.super.apply(this, arguments)} else {return CODE(object)}
  })

  // Create Class with encoded
  function CODE(structure) {
    // Structured class
    return extend(PRIMITIVE(tagNumber), function (object) {
      Class.super.call(this, object)
    }, {
      // Transformation to code values
      encode: function (format) {
        return encode(format, structure[this.object], tagNumber)
      },
    }, {
      decode: function (source) {
        const id = decode(source, tagNumber)
        for (const name in structure) {
          if (id === structure[name]) {return new this(name)}
        }
        assert(true)
      },
    })
  }
  return Class
}

const INTEGER = PRIMITIVE_CODE(0x02)

const ENUMERATED = PRIMITIVE_CODE(0x0a)

const OCTET_STRING = (function () {
  // Base class primitive
  var Class = extend(PRIMITIVE(0x04), function (object) {
    if (this instanceof Class) {Class.super.apply(this, arguments)} else {return WRAPPING(object)}
  })
  // Wrapping class
  function WRAPPING(WrappedClass) {
    if (WrappedClass) {
      return extend(WrappedClass, {
        encode: function (format) {
          return encode(format, WrappedClass.method('encode').call(this, true), 0x04)
        },
      }, {
        decode: function (source) {
          return WrappedClass.decode.call(this, decode(source, 0x04))
        },
      })
    } return Class
  }
  return Class
})()

const BIT_STRING = (function () {
  // Base class primitive
  var Class = extend(PRIMITIVE(0x03), function (object) {
    if (this instanceof Class) {Class.super.apply(this, arguments)} else if (typeof object === 'object') {return MASK(object)} else {return WRAPPING(object)}
  })

  // Wrapping class
  function WRAPPING(WrappedClass) {
    if (WrappedClass) {
      return extend(WrappedClass, {
        encode: function (format) {
          return encode(format, WrappedClass.method('encode').call(this, true), 0x03)
        },
      }, {
        decode: function (source) {
          return WrappedClass.decode.call(this, decode(source, 0x03))
        },
      })
    } return Class
  }

  // Create new class for a mask
  function MASK(structure) {
    // Bit string masked class
    return extend(ASN1Object, function (object, numbits) {
      ASN1Object.call(this, object)
      this.numbits = numbits || 0
    }, {
      encode: function (format) {
        let object = this.object, data = []
        if (object instanceof Array) {
          for (var i = 0, n = object.length; i < n; i++) {
            const j = structure[object[i]]
            if (j !== undefined) {data[j] = '1'}
          }
          for (var i = 0, n = Math.max(data.length, this.numbits); i < n; i++) {
            if (!data[i]) {data[i] = '0'}
          }
          data = data.join('')
        } else {data = '0'}
        return encode(format, data, 0x03)
      },
    }, {
      // Transformation to array of values
      decode: function (source) {
        const data = decode(source, 0x03), object = []
        for (const name in structure) {
          const i = structure[name]
          if (data.charAt(i) === '1') {object.push(name)}
        }
        return new this(object, data.length)
      },
    })
  }

  return Class
})()

// Combine sequence object properties with owner object
const COMBINE = function (Class) {
  Class.combine = function (owner, valueName) {
    for (const name in Class.prototype) {
      if (Class.prototype.hasOwnProperty(name) && !owner.hasProperty(name)) {
        defineProperty(owner, name, (function (name) {
          return {
            get: function () {
              // Get object property
              return this[valueName] && this[valueName][name]
            },
            set: function (object) {
              // Set object property
              if (!this[valueName]) {this[valueName] = {}}
              this[valueName][name] = object
            },
            configurable: false,
            enumerable: true,
          }
        })(name))
      }
    }
  }
  return Class
}

const SEQUENCE = function (structure, uniformTitle) {

  /**
     * Create SEQUENCE ASN.1 metaclass
     *
     * @class GostASN1.Sequence
     * @param {(Object|FormatedData)} object Initialization object
     * @param {boolean} check Check structure after initialization
     */
  const Class = extend(ASN1Object, function (object, check) {
    // Define hidden properties
    defineProperty(this, 'items', {
      writable: true,
      value: {},
    })
    if (typeof object === 'string' || object instanceof CryptoOperationData) {this.decode(object)} else if (object !== undefined) {
      this.object = object
      // Check structure
      if (check) {this.check()}
    }
  }, {
    object: {
      get: function () {
        return this
      },
      set: function (object) {
        if (object instanceof Class) {
          // Set the same sequence class
          this.items = object.items
          for (var name in structure) {
            var ItemClass = this.getItemClass(name, this.items)
            if (ItemClass.combine) {ItemClass.combine(this, name)}
          }
        } else {
          // Set other object structure
          const data = {}
          for (var name in structure) {
            const item = object[name]
            var ItemClass = this.getItemClass(name, data)
            if (item !== undefined) {
              data[name] = new ItemClass(item)
            } else if (ItemClass.combine) {
              // Create combined object
              data[name] = new ItemClass(object)
            }
            if (ItemClass.combine) {ItemClass.combine(this, name)}
          }
          this.items = data
        }
      },
    },
    getItemClass: function (name, items) {
      return structure[name]
    },
    /**
         * Encode the object
         *
         * @memberOf GostASN1.Sequence
         * @instance
         * @param {string} format Encoding format 'DER', 'CER' or 'PEM'
         * @returns {FormatedData}
         */
    encode: function (format) {
      const source = [], items = this.items
      // Encode objects in structure
      for (const name in structure) {
        // console.log(name, 'encoding...', items[name]);
        if (items[name]) {
          const encoded = items[name].encode(true)// Source from object
          if (encoded !== undefined) // Can be optional
          {source.push(encoded)}

        }
      }
      return encode(format, source, 0x10, 0, true, uniformTitle)
    },
    /**
         * Decode the source to self object
         *
         * @memberOf GostASN1.Sequence
         * @instance
         * @param {FormatedData} source Encoded data
         */
    decode: function (source) {
      this.object = this.constructor.decode(source)
    },
    /**
         * Check the object structure
         *
         * @memberOf GostASN1.Sequence
         * @instance
         */
    check: function () {
      this.constructor.decode(this.encode(true))
    },
  }, {
    /**
         * Encode data values with creating object
         *
         * @memberOf GostASN1.Sequence
         * @static
         * @param {Object} object Javascript object to encoding
         * @param {string} format Encoding format 'DER', 'CER' or 'PEM'
         * @returns {FormatedData}
         */
    encode: function (object, format) {
      return new this(object).encode(format)
    },
    /**
         * Decode source and create object
         *
         * @memberOf GostASN1.Sequence
         * @static
         * @param {FormatedData} source Encoded data
         * @returns {GostASN1.Sequence}
         *
         */
    decode: function (source) {
      // Decode structure
      source = decode(source, 0x10, 0, true, uniformTitle)
      let i = 0, result = new this(), data = result.items = {}
      for (const name in structure) {
        // console.log(name, 'decoding...');
        // try to create and decode object
        const ItemClass = result.getItemClass(name, data)
        const item = ItemClass.decode(source[i])
        // success? item can be optional
        if (item !== undefined) {
          data[name] = item
          if (ItemClass.combine) {ItemClass.combine(result, name)}
          i++
        }
      }
      return result
    },
  })

  // Append structure items
  for (const name in structure) {
    defineProperty(Class.prototype, name, (function (name) {
      return {
        get: function () {
          // Get object property
          return this.items[name] && this.items[name].object
        },
        set: function (object) {
          // Set object property
          if (object !== undefined) {
            const ItemClass = this.getItemClass(name, this.items)
            this.items[name] = new ItemClass(object)
          } else {delete this.items[name]}
        },
        configurable: false,
        enumerable: !structure[name].combine,
      }
    })(name))
    if (structure[name].combine) {structure[name].combine(Class.prototype, name)}
  }
  return Class
}

const ATTRIBUTE = function (structure, typeName, valueName, ownerDafaultType, uniformName) {

  const BaseClass = SEQUENCE(structure, uniformName)

  // Define attribute sequence
  var DEFINE = function (typeSet, defaultType) {

    typeName = typeName || 'type'
    valueName = valueName || 'value'
    defaultType = defaultType || ownerDafaultType || ANY

    var Class = extend(BaseClass, function (object) {
      // Constructor - "matrioshka"
      if (this instanceof Class) {
        // Call super
        BaseClass.apply(this, arguments)
      } else {return DEFINE.apply(this, arguments)}
    }, {
      getItemClass: function (name, items) {
        let ItemClass = structure[name]
        if (valueName === name) {
          // Define type of value attribute based on type attribute
          let type, typeId = items && items[typeName]
          if (typeId) {
            const id = typeId.object
            if (typeSet) {
              if (typeof typeSet === 'function') {type = typeSet(id)} else {type = typeSet[id]}
            }
          }
          type = type || defaultType || ANY
          ItemClass = ItemClass === ANY ? type :
            ItemClass(type)
        }
        return ItemClass
      },
    })

    // Redefine type property
    defineProperty(Class.prototype, typeName, {
      get: function () {
        // Get value property of object
        return this.items[typeName] && this.items[typeName].object
      },
      set: function () {
        // Can't set type definition property separatery
        assert(true)
      },
      configurable: false,
      enumerable: true,
    })

    return Class
  }

  return DEFINE()
}


const OBJECT_IDENTIFIER = extend(ASN1Object, {
  encode: function (format) {
    let object = this.object
    object = /^(\d+\.)+\d+$/.test(object) ? object : identifiers[object]
    assert(!object)
    return encode(format, object, 0x06)
  },
}, {
  decode: function (source) {
    const object = decode(source, 0x06)
    return new this(names[object] || object)
  },
})

const IMPLICIT = function (Class) {
  Class = Class || ANY
  // Add constracted tag
  return extend(Class, {
    encode: function (format) {
      // Format encoding without CTX header
      const source = Class.method('encode').call(this, format)
      if (typeof source === 'string' || source instanceof CryptoOperationData) {return source}
      if (source.tagNumber !== 0x04 && source.tagClass === 0 &&
                !(source.object instanceof Array))
      // Encode primitive source
      {return { object: BER.encode(source, 'DER', true) }}
      return { object: source.object }
    },
  }, {
    decode: function (source) {
      if (typeof source === 'string' || source instanceof CryptoOperationData) {
        return Class.decode.call(this, source)
      }
      source = {
        object: source.object,
        header: source.header,
        content: source.content,
      }
      return Class.decode.call(this, source)

    },
  })
}

const EXPLICIT = function (Class) {
  Class = Class || ANY
  // Add constracted tag
  return extend(Class, {
    encode: function (format) {
      // Format encoding without CTX header
      const source = Class.method('encode').call(this, format)
      if (typeof source === 'string' || source instanceof CryptoOperationData) {return source}
      return { object: [source] }
    },
  }, {
    decode: function (source) {
      if (typeof source === 'string' || source instanceof CryptoOperationData) {
        return Class.decode.call(this, source)
      } return Class.decode.call(this, source.object[0])
    },
  })
}

const CTX = function (number, ContentClass) {
  function CTX() {
    ContentClass.apply(this, arguments)
  }
  // Create CTX number class with wrapped content class
  return extend(ContentClass, CTX, {
    encode: function (format) {
      const source = ContentClass.method('encode').call(this, format)
      if (typeof source === 'string' || source instanceof CryptoOperationData) {return source}
      source.tagNumber = number
      source.tagClass = 0x02
      source.tagConstructed = source.object instanceof Array
      return source
    },
  }, {
    decode: function (source) {
      // Format decoding without CTX
      assert(source.tagNumber !== undefined &&
                (source.tagClass !== 0x02 || source.tagNumber !== number))
      return ContentClass.decode.call(this, source)
    },
  })
}

const ARRAY_OF = function (tagNumber) {

  return function (ItemClassDef, typeAndValue) {
    // Difininition of item class
    ItemClassDef = ItemClassDef || ANY

    // Metaclass definition
    var DEFINE = function (typeSet, defaultType) {

      // Define item class
      const ItemClass = typeof ItemClassDef === 'function' &&
                typeSet !== undefined ?
        ItemClassDef(typeSet, defaultType) : ItemClassDef

      if (typeAndValue) {
        /**
                 * Create class with type and value structure<br><br>
                 *
                 * SET OF attribute and SEQUENCE OF attribute metaclass
                 *
                 * @class GostASN1.Set
                 * @param {Object} object object value
                 */
        var Class = extend(ASN1Object, function (object) {
          // Constructor - "matrioshka"
          if (this instanceof Class) {
            // Define hidden items property
            defineProperty(this, 'items', {
              writable: true,
              value: {},
            })
            // Call super
            ASN1Object.call(this, object || {})
          } else {return DEFINE.apply(this, arguments)}
        }, {
          object: {
            get: function () {
              // refresh items from object properties
              this.read()
              return this
            },
            set: function (object) {
              if (object instanceof Class) {
                object.read()
                this.items = object.items
              } else {
                // Set other object structure
                const data = {}
                for (const id in object) {
                  const item = object[id]
                  data[id] = this.createItem(item, id)
                }
                this.items = data
              }
              // refresh object properties to items
              this.reset()
            },
          },
          createItem: function (value, type) {
            if (typeAndValue) {
              var object = {}
              object[typeAndValue.typeName] = type
              object[typeAndValue.valueName] = value
            } else {object = value}
            return new ItemClass(object)
          },
          getItemValue: function (id) {
            const item = this.items[id]
            return typeAndValue ? item.object[typeAndValue.valueName] : item.object
          },
          setItemValue: function (id, value) {
            const item = this.items[id]
            if (typeAndValue) {item.object[typeAndValue.valueName] = value} else {item.object = value}
          },
          isItemType: function (id) {
            return typeAndValue ? identifiers[id] : !isNaN(parseInt(id))
          },
          reset: function () {
            // remove unused properties
            const items = this.items
            for (var id in this) {
              if (this.hasOwnProperty(id) && !this.items[id] &&
                                this.isItemType(id)) {delete this[id]}
            }
            // add new properties
            for (var id in items) {this[id] = this.getItemValue(id)}
          },
          read: function () {
            const items = this.items
            for (const id in this) {
              if (this.isItemType(id)) {
                if (!this.items[id]) {
                  items[id] = this.createItem(this[id], id)
                  this[id] = this.getItemValue(id)
                } else if (this.getItemValue(id) !== this[id]) {
                  this.setItemValue(id, this[id])
                }
              }
            }
          },
          /**
                     * Encode the object
                     *
                     * @memberOf GostASN1.Set
                     * @instance
                     * @param {string} format Encoding format 'DER', 'CER' or 'PEM'
                     * @returns {FormatedData}
                     */
          encode: function (format) {
            // refresh items from object properties
            this.read()
            // repare source
            const object = this.items, source = []
            for (const id in object) {
              // console.log(id, object[id], 'encoding...');
              const encoded = object[id].encode(true)
              if (encoded !== undefined) {source.push(encoded)}
            }
            return encode(format, source, tagNumber, 0, true)
          },
          /**
                     * Decode the source to self object
                     *
                     * @memberOf GostASN1.Set
                     * @instance
                     * @param {FormatedData} source Encoded data
                     */
          decode: function (source) {
            this.object = this.constructor.decode(source)
          },
          /**
                     * Check the object structure
                     *
                     * @memberOf GostASN1.Set
                     * @instance
                     */
          check: function () {
            this.constructor.decode(this.encode(true))
          },
        }, {
          /**
                     * Encode data values with creating object
                     *
                     * @memberOf GostASN1.Set
                     * @static
                     * @param {Object} object Javascript object to encoding
                     * @param {string} format Encoding format 'DER', 'CER' or 'PEM'
                     * @returns {FormatedData}
                     */
          encode: function (object, format) {
            return new this(object).encode(format)
          },
          /**
                     * Decode source and create object
                     *
                     * @memberOf GostASN1.Set
                     * @static
                     * @param {FormatedData} source Encoded data
                     * @returns {GostASN1.Sequence}
                     *
                     */
          decode: function (source) {
            // Decode structure
            source = decode(source, tagNumber, 0, true)
            const result = new this(), data = result.items = {}
            for (let i = 0, n = source.length; i < n; i++) {
              const item = ItemClass.decode(source[i])
              const id = typeAndValue ? item.object[typeAndValue.typeName] : i
              data[id] = item
            }
            result.reset()
            return result
          },
        })

        return Class
      }
      // Create array class
      var ArrayClass = extend(ASN1Object, function (object) {
        // Constructor - "matrioshka"
        if (this instanceof ArrayClass) {
          // Define hidden items property
          defineProperties(this, {
            items: {
              writable: true,
              value: [],
            },
            values: {
              writable: true,
              value: [],
            },
          })
          // Call super
          ASN1Object.call(this, object || [])
        } else {return DEFINE.apply(this, arguments)}
      }, {
        object: {
          get: function () {
            // refresh items from object properties
            this.read()
            return this.values
          },
          set: function (object) {
            if (object instanceof ArrayClass) {
              object.read()
              this.items = object.items
            } else {
              // Set other object structure
              const data = []
              for (let i = 0, n = object.length; i < n; i++) {data[i] = new ItemClass(object[i])}
              this.items = data
            }
            // refresh object properties to items
            this.reset()
          },
        },
        encode: function (format) {
          // refresh items from object properties
          this.read()
          // repare source
          const data = this.items, source = []
          for (let i = 0, n = data.length; i < n; i++) {
            const encoded = data[i].encode(true)
            if (encoded !== undefined) {source.push(encoded)}
          }
          return encode(format, source, tagNumber, 0, true)
        },
        decode: function (source) {
          this.object = this.constructor.decode(source)
        },
        check: function () {
          this.constructor.decode(this.encode(true))
        },
        reset: function () {
          // remove unused properties
          for (let i = 0, n = this.items.length; i < n; i++) {this.values.push(this.items[i].object)}
        },
        read: function () {
          const items = this.items, values = this.values
          for (let i = 0, n = values.length; i < n; i++) {
            if (!this.items[i]) {
              items[i] = new ItemClass(values[i])
              values[i] = items[i].object
            } else if (items[i].object !== values[i]) {items[i].object = values[i]}
          }
        },
      }, {
        encode: function (object, format) {
          return new this(object).encode(format)
        },
        decode: function (source) {
          source = decode(source, tagNumber, 0, true)
          const result = new this()
          result.items = []
          for (let i = 0, n = source.length; i < n; i++) {result.items.push(ItemClass.decode(source[i]))}
          result.reset()
          return result
        },
      })

      return ArrayClass

    }
    return DEFINE() // Create simple class w/o any parameters
  }
}

const SEQUENCE_OF = ARRAY_OF(0x10)

const SET_OF = ARRAY_OF(0x11)

const ENCLOSURE = function (BaseClass, modifier) {
  if (modifier) {
    const Class = extend(ASN1Object, {
      object: {
        get: function () {
          if (this.item) {return modifier.decode(this.item.object)}
          return undefined
        },
        set: function (object) {
          if (object !== undefined) {this.item = new BaseClass(modifier.encode(object))} else {delete this.item}
        },
      },
      encode: function (format) {
        return this.item.encode(format)
      },
    }, {
      decode: function (source) {
        const result = new this()
        result.item = BaseClass.decode(source)
        return result
      },
    })
    for (const name in BaseClass) {
      if (!Class[name]) {Class[name] = BaseClass[name]}
    }
    return Class
  } return BaseClass
}

const SET_OF_SINGLE = function (ItemClass) {

  const Class = ENCLOSURE(SET_OF(ItemClass), {
    encode: function (item) {
      return [item]
    },
    decode: function (item) {
      return item[0]
    },
  })
  return Class
}

const CHOICE = function (structure, define) {

  return extend(ASN1Object, {
    object: {
      get: function () {
        return this.item && this.item.object
      },
      set: function (object) {
        // Try to find appropriate type in structure
        if (object instanceof ASN1Object) {
          for (var name in structure) {
            if (object instanceof structure[name]) {
              this.item = object
              return
            }
          }
        }
        // Define class
        var name = typeof define === 'function' ? define(object) : define
        assert(!name || !structure[name])
        object = new structure[name](object)
        this.item = object
      },
    },
    encode: function (format) {
      // Already in class
      return this.item.encode(format)
    },
  }, {
    decode: function (source) {
      // Try to find class structure
      for (const name in structure) {
        try {
          const item = structure[name].decode(source)
          if (item !== undefined) {return new this(item)}
        } catch (e) {
        }
      }
      assert(true)
    },
  })
}

const ENCAPSULATES = function (WrappedClass) {
  WrappedClass = WrappedClass || ANY
  // BER Encode/Decode values
  return extend(WrappedClass, {
    encode: function () {
      return BER.encode(WrappedClass.method('encode').call(this, true))
    },
  }, {
    encode: function (object, format) {
      return new this(object).encode(format)
    },
    decode: function (source) {
      return WrappedClass.decode.call(this, BER.decode(source))
    },
  })
}

const DEFAULT = function (Class, optional) {
  Class = Class || ANY
  return extend(Class, {
    encode: function (format) {
      if (this.object === optional) {return undefined}
      return Class.method('encode').call(this, format)
    },
  }, {
    decode: function (source) {
      if (source === undefined) {return new this(optional)}
      try {
        return Class.decode.call(this, source)
      } catch (e) {
        return undefined
      }
    },
  })
}

const OPTIONAL = function (Class) {
  Class = Class || ANY
  return extend(Class, {}, {
    decode: function (source) {
      if (source === undefined) {return undefined}
      try {
        return Class.decode.call(this, source)
      } catch (e) {
        return undefined
      }
    },
  })
}

const DEFAULT_NULL = function (Class, optional) {
  Class = Class || ANY
  return extend(Class, {
    encode: function (format) {
      if (this.object === optional) {return new NULL(null).encode(format)}
      return Class.method('encode').call(this, format)
    },
  }, {
    decode: function (source) {
      if (source === undefined) {return undefined}
      if (source === null ||
                (source.tagNumber === 0x05 && source.tagClass === 0)) {return new this(optional)}
      try {
        return Class.decode.call(this, source)
      } catch (e) {
        return undefined
      }
    },
  })
}

// </editor-fold>

/*
 * Certificate Version, Name, Attributes, Validity
 *
 * http://tools.ietf.org/html/rfc5280
 *
 */ // <editor-fold defaultstate="collapsed">

const DirectoryString = CHOICE({
  teletexString: TeletexString,
  printableString: PrintableString,
  universalString: UniversalString,
  utf8String: UTF8String,
  bmpString: BMPString,
  numericString: NumericString,
}, function (value) {
  // PrintableString - for characters and symbols with no spaces, overrise UTF8String
  return /^[A-Za-z0-9\.@\+\-\:\=\\\/\?\!\#\$\%\^\&\*\(\)\[\]\{\}\>\<\|\~]*$/.test(value) ? 'printableString' : 'utf8String'
})

const Time = CHOICE({
  utcTime: UTCTime,
  generalTime: GeneralizedTime,
}, function (value) {
  return value.getYear() >= 2050 ? 'generalTime' : 'utcTime'
})

// Attribute
const AttributeType = OBJECT_IDENTIFIER

const AttributeValue = ANY

const AttributeTypeAndValue = ATTRIBUTE({
  type: AttributeType,
  value: AttributeValue,
})

const typeAndValue = {
  typeName: 'type',
  valueName: 'value',
}

/**
 * X.501 type Name
 * The Name describes a hierarchical name composed of attributes, such
 * as country name, and corresponding values, such as US.  The type of
 * the component AttributeValue is determined by the AttributeType; in
 * general it will be a DirectoryString.

 * The DirectoryString type is defined as a choice of PrintableString,
 * TeletexString, BMPString, UTF8String, and UniversalString.  The
 * UTF8String encoding [RFC 2279] is the preferred encoding, and all
 * certificates issued after December 31, 2003 MUST use the UTF8String
 * encoding of DirectoryString.
 *
 * Standard sets of attributes have been defined in the X.500 series of
 * specifications [X.520].  Implementations of this specification MUST
 * be prepared to receive the following standard attribute types in
 * issuer and subject (section 4.1.2.6) names:
 *  <ul>
 *      <li>country,</li>
 *      <li>organization,</li>
 *      <li>organizational-unit,</li>
 *      <li>distinguished name qualifier,</li>
 *      <li>state or province name,</li>
 *      <li>common name (e.g., "Susan Housley"), and</li>
 *      <li>serial number.</li>
 *  </ul>
 * In addition, implementations of this specification SHOULD be prepared
 * to receive the following standard attribute types in issuer and
 * subject names:
 *  <ul>
 *      <li>locality,</li>
 *      <li>title,</li>
 *      <li>surname,</li>
 *      <li>given name,</li>
 *      <li>initials,</li>
 *      <li>pseudonym, and</li>
 *      <li>generation qualifier (e.g., "Jr.", "3rd", or "IV").</li>
 *  </ul>
 The syntax for type Name:
 *  <pre>
 *  Name ::= CHOICE {
 *    rdnSequence RDNSequence }
 *
 *  RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 *  RelativeDistinguishedName ::=
 *    SET OF AttributeTypeAndValue
 *
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 *
 *  DirectoryString ::= CHOICE {
 *        teletexString           TeletexString (SIZE (1..MAX)),
 *        printableString         PrintableString (SIZE (1..MAX)),
 *        universalString         UniversalString (SIZE (1..MAX)),
 *        utf8String              UTF8String (SIZE (1..MAX)),
 *        bmpString               BMPString (SIZE (1..MAX)) }
 *  </pre>
 * @class GostASN1.Name
 */
const RelativeDistinguishedName = SET_OF_SINGLE(AttributeTypeAndValue({
  serialName: PrintableString,
  countryName: PrintableString,
  dnQualifier: PrintableString,
  emailAddress: IA5String,
  domainComponent: IA5String,
  SNILS: NumericString,
  OGRN: NumericString,
  INN: NumericString,
}, DirectoryString))

const RDNSequence = SEQUENCE_OF(RelativeDistinguishedName, typeAndValue)()

const Name = CHOICE({
  // only one possibility for now
  rdnSequence: RDNSequence,
}, 'rdnSequence')

/**
 * Validity
 * @class GostASN1.Validity
 * @extends GostASN1.Sequence
 */
const Validity = COMBINE(SEQUENCE({
  notBefore: Time,
  notAfter: Time,
}))

const Version = INTEGER

const Attribute = ATTRIBUTE({
  type: OBJECT_IDENTIFIER,
  value: ANY,
})

/**
 * Type and Value Attributes <br>
 *
 * Suggested naming attributes: Definition of the following
 * information object set may be augmented to meet local
 * requirements.  Note that deleting members of the set may
 * prevent interoperability with conforming implementations.
 * presented in pairs: the AttributeType followed by the type
 * definition for the corresponding AttributeValue
 *
 * @class GostASN1.Attributes
 * @extends GostASN1.Set
 */
const Attributes = SET_OF(Attribute, typeAndValue)

const AttributeSequence = SEQUENCE_OF(Attribute, typeAndValue)
// </editor-fold>

/*
 * Algorithm identifiers
 *
 * http://tools.ietf.org/html/rfc3279
 * http://tools.ietf.org/html/rfc4357
 * http://tools.ietf.org/html/rfc2898
 *
 */ // <editor-fold defaultstate="collapsed">

const FieldElement = INTEGER
const Curve = SEQUENCE({
  a: FieldElement,
  b: FieldElement,
  seed: OPTIONAL(BIT_STRING),
})

const ECPoint = OCTET_STRING(extend(ASN1Object, {
  encode: function () {
    const value = this.object
    const len = Math.max(npw2(value.x.length - 2), npw2(value.y.length - 2)) / 2,
      r = new Uint8Array(2 * len + 1)
    r[0] = 0x04
    r.set(new Uint8Array(SInt.decode(value.x, false, len)), 1) // x
    r.set(new Uint8Array(SInt.decode(value.y, false, len)), len + 1) // y
    return r.buffer
  },
}, {
  decode: function (value) {
    const len = (value.byteLength - 1) / 2
    return new this({
      x: SInt.encode(new Uint8Array(value, 1, len)),
      y: SInt.encode(new Uint8Array(value, len + 1, len)),
    })
  },
}))

const FieldID = SEQUENCE({
  fieldType: OBJECT_IDENTIFIER,
  parameters: INTEGER,
})

const ECParameters = SEQUENCE({
  version: Version, // version is always 1
  fieldID: FieldID, // identifies the finite field over which the curve is defined
  curve: Curve, // coefficients a and b of the elliptic curve
  base: ECPoint, // specifies the base point P on the elliptic curve
  order: INTEGER, // the order n of the base point
  cofactor: OPTIONAL(INTEGER),
}) // The integer h = #E(Fq)/n

const GostR3410Parameters = SEQUENCE({
  publicKeyParamSet: OBJECT_IDENTIFIER,
  digestParamSet: OBJECT_IDENTIFIER,
  encryptionParamSet: OPTIONAL(OBJECT_IDENTIFIER),
})

const GostR3411Parameters = DEFAULT_NULL(OBJECT_IDENTIFIER, 'id-GostR3411-94-CryptoProParamSet')

const ECDHParameters = CHOICE({
  namedParameters: OBJECT_IDENTIFIER,
  ecParameters: ECParameters,
  implicitly: OPTIONAL(NULL),
}, function (value) {
  return typeof value === 'string' || value instanceof String ?
    'namedParameters' : 'ecParameters'
})

const Algorithm = function (paramType, modifier) {
  return ENCLOSURE(SEQUENCE({
    algorithm: OBJECT_IDENTIFIER,
    parameters: OPTIONAL(paramType),
  }), modifier)
}

const AlgorithmIdentifier = (function () {

  var DefaultAlgorithm = Algorithm(ANY),
    Class = extend(ASN1Object, function (object) {
      if (this instanceof Class) {Class.super.apply(this, arguments)} else {return DEFINE(object)}
    }, {
      encode: function (format) {
        return new DefaultAlgorithm(this.object).encode(format)
      },
    }, {
      decode: function (source) {
        return new this(DefaultAlgorithm.decode(source).object)
      },
    })

  var DEFINE = function (algorithmSet) {

    return extend(ASN1Object, {
      object: {
        get: function () {
          if (this.item) {return this.item.object}
          return undefined
        },
        set: function (object) {
          if (object) {
            const ItemClass = algorithmSet[object.id]
            if (!ItemClass) {throw new Error('Algorithm not supported')}
            this.item = new ItemClass(object)
          } else {delete this.item}
        },
      },
      encode: function (format) {
        return this.item.encode(format)
      },
    }, {
      decode: function (source) {
        // Decode PEM
        if (typeof source === 'string') {source = PEM.decode(source, undefined, false)}
        // Decode binary data
        if (source instanceof CryptoOperationData) {source = BER.decode(source)}
        const ItemClass = algorithmSet[names[source.object[0].object]]
        if (ItemClass) {
          const result = new this()
          result.item = ItemClass.decode(source)
          return result
        } throw new Error('Algorithm not supported')
      },
    })
  }

  return Class
})()

const ECDHKeyAlgorithm = Algorithm(ECDHParameters, {
  encode: function (value) {
    let params
    if (typeof value.namedCurve === 'string') {params = attributes['namedCurve'][value.namedCurve]} else {
      params = {
        version: 1,
        fieldID: {
          fieldType: 'id-prime-Field',
          parameters: value.curve.p,
        },
        curve: {
          a: value.curve.a,
          b: value.curve.b,
        },
        base: {
          x: value.curve.x,
          y: value.curve.y,
        },
        order: value.curve.q,
        cofactor: 1,
      }
    }
    return {
      algorithm: value.id,
      parameters: params,
    }
  },
  decode: function (value) {
    let params = value.parameters,
      result = algorithms[value.algorithm]
    if (typeof params === 'string' || params instanceof String) {
      result = expand(result, parameters[params])
    } else if (typeof params === 'object') {
      result = expand(result, {
        curve: {
          p: params.fieldID.parameters,
          a: params.curve.a,
          b: params.curve.b,
          x: params.base.x,
          y: params.base.y,
          q: params.order,
        },
      })
    } else {throw new DataError('Invalid key paramters')}
    return result
  },
})

const GostKeyAlgorithm = Algorithm(GostR3410Parameters, {
  encode: function (value) {
    const paramName = value.namedCurve ? 'namedCurve' : 'namedParam',
      sBox = (value.name.indexOf('-94') >= 0 || value.name.indexOf('-2001') >= 0 ||
                value.version === 1994 || value.version === 2001) ? value.sBox || 'D-A' :
        (value.name.indexOf('-512') >= 0 || value.length === 512) ? 'D-512' : 'D-256'
    return {
      algorithm: value.id,
      parameters: {
        publicKeyParamSet: attributes[paramName][value[paramName]],
        digestParamSet: attributes['sBox'][sBox],
        encryptionParamSet: value.encParams && value.encParams.sBox ?
          attributes['sBox'][value.encParams.sBox] : undefined,
      },
    }
  },
  decode: function (value) {
    const params = value.parameters,
      algorithm = expand(algorithms[value.algorithm],
        parameters[params.publicKeyParamSet],
        parameters[params.digestParamSet])
    if (params.encryptionParamSet) {algorithm.encParams = parameters[params.encryptionParamSet]}
    return algorithm
  },
})

const AlgorithmWithNoParam = Algorithm(ANY, {
  encode: function (value) {
    return { algorithm: value.id }
  },
  decode: function (value) {
    return algorithms[value.algorithm]
  },
})

const AlgorithmWithNullParam = Algorithm(NULL, {
  encode: function (value) {
    return {
      algorithm: value.id,
      parameters: null,
    }
  },
  decode: function (value) {
    return algorithms[value.algorithm]
  },
})

const Gost341194DigestAlgorithm = Algorithm(GostR3411Parameters, {
  encode: function (value) {
    return {
      algorithm: value.id,
      parameters: attributes['sBox'][value.sBox || (value.hash && value.hash.sBox) || 'D-A'],
    }
  },
  decode: function (value) {
    let algorithm = expand(algorithms[value.algorithm]),
      parameter = parameters[value.parameters]
    if (algorithm.hash) {algorithm.hash = expand(algorithm.hash, parameter)} else {algorithm = expand(algorithm, parameter)}
    return algorithm
  },
})

const KeyAlgorithmIdentifier = AlgorithmIdentifier({
  ecdsa: ECDHKeyAlgorithm,
  noSignature: AlgorithmWithNullParam,
  rsaEncryption: AlgorithmWithNullParam,
  'id-sc-gostR3410-2001': ECDHKeyAlgorithm,
  'id-GostR3410-2001': GostKeyAlgorithm,
  'id-GostR3410-94': GostKeyAlgorithm,
  'id-GostR3410-2001DH': GostKeyAlgorithm,
  'id-GostR3410-94DH': GostKeyAlgorithm,
  'id-tc26-gost3410-12-256': GostKeyAlgorithm,
  'id-tc26-gost3410-12-512': GostKeyAlgorithm,
  'id-tc26-agreement-gost-3410-12-256': GostKeyAlgorithm,
  'id-tc26-agreement-gost-3410-12-512': GostKeyAlgorithm,
  'id-sc-gost28147-gfb': AlgorithmWithNoParam,
  'id-Gost28147-89': AlgorithmWithNoParam,
})

const SignatureAlgorithmIdentifier = AlgorithmIdentifier({
  noSignature: AlgorithmWithNullParam,
  rsaEncryption: AlgorithmWithNullParam,
  sha1withRSAEncryption: AlgorithmWithNullParam,
  sha256withRSAEncryption: AlgorithmWithNullParam,
  sha384withRSAEncryption: AlgorithmWithNullParam,
  sha512withRSAEncryption: AlgorithmWithNullParam,
  'ecdsa': AlgorithmWithNoParam,
  'ecdsa-with-SHA1': AlgorithmWithNoParam,
  'ecdsa-with-SHA256': AlgorithmWithNoParam,
  'ecdsa-with-SHA384': AlgorithmWithNoParam,
  'ecdsa-with-SHA512': AlgorithmWithNoParam,
  'id-GostR3410-94': AlgorithmWithNullParam,
  'id-GostR3410-2001': AlgorithmWithNullParam,
  'id-GostR3411-94-with-GostR3410-2001': AlgorithmWithNoParam,
  'id-GostR3411-94-with-GostR3410-94': AlgorithmWithNoParam,
  'id-tc26-gost3410-12-256': AlgorithmWithNullParam,
  'id-tc26-gost3410-12-512': AlgorithmWithNullParam,
  'id-tc26-signwithdigest-gost3410-12-94': AlgorithmWithNoParam,
  'id-tc26-signwithdigest-gost3410-12-256': AlgorithmWithNoParam,
  'id-tc26-signwithdigest-gost3410-12-512': AlgorithmWithNoParam,
  'id-sc-gostR3410-94': AlgorithmWithNullParam,
  'id-sc-gostR3410-2001': AlgorithmWithNullParam,
  'id-sc-gostR3411-94-with-gostR3410-94': AlgorithmWithNullParam,
  'id-sc-gostR3411-94-with-gostR3410-2001': AlgorithmWithNullParam,
})

const DigestAlgorithmIdentifier = AlgorithmIdentifier({
  sha1: AlgorithmWithNoParam,
  sha256: AlgorithmWithNullParam,
  sha384: AlgorithmWithNullParam,
  sha512: AlgorithmWithNullParam,
  'id-GostR3411-94': Gost341194DigestAlgorithm,
  'id-tc26-gost3411-94': Gost341194DigestAlgorithm,
  'id-tc26-gost3411-12-256': AlgorithmWithNullParam,
  'id-tc26-gost3411-12-512': AlgorithmWithNullParam,
  'id-sc-gostR3411-94': AlgorithmWithNoParam,
})

const Gost2814789Key = OCTET_STRING //(SIZE (32))

const Gost2814789MAC = OCTET_STRING // (SIZE (1..4))

const Gost2814789ParamSet = OBJECT_IDENTIFIER

const Gost2814789IV = OCTET_STRING // (SIZE (8))

const Gost2814789Parameters = SEQUENCE({
  iv: Gost2814789IV,
  encryptionParamSet: Gost2814789ParamSet,
})

const Gost2814789KeyWrapParameters = SEQUENCE({
  encryptionParamSet: Gost2814789ParamSet,
  ukm: OPTIONAL(OCTET_STRING),
}) // (SIZE (8)) must be absent in key agreement

const Gost2814789Algorithm = Algorithm(Gost2814789Parameters, {
  encode: function (value) {
    return {
      algorithm: value.id,
      parameters: {
        iv: value.iv,
        encryptionParamSet: attributes['sBox'][value.sBox || 'E-A'],
      },
    }
  },
  decode: function (value) {
    const algorithm = expand(algorithms[value.algorithm],
      parameters[value.parameters.encryptionParamSet])
    algorithm.iv = value.parameters.iv
    return algorithm
  },
})

const SCGostAlgorithm = Algorithm(Gost2814789IV, {
  encode: function (value) {
    return {
      algorithm: value.id,
      parameters: value.iv,
    }
  },
  decode: function (value) {
    const algorithm = expand(algorithms[value.algorithm])
    algorithm.iv = value.parameters || new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0])
    return algorithm
  },
})

const GostKeyWrapAlgorithm = Algorithm(Gost2814789KeyWrapParameters, {
  encode: function (value) {
    return {
      algorithm: value.id,
      parameters: {
        encryptionParamSet: attributes['sBox'][value.sBox || 'E-A'],
        ukm: value.ukm,
      },
    }
  },
  decode: function (value) {
    const algorithm = expand(algorithms[value.algorithm],
      parameters[value.parameters.encryptionParamSet])
    if (value.parameters.ukm) {algorithm.ukm = value.parameters.ukm}
    return algorithm
  },
})

const KeyWrapAlgorithmIdentifier = AlgorithmIdentifier({
  'id-Gost28147-89-None-KeyWrap': GostKeyWrapAlgorithm,
  'id-Gost28147-89-CryptoPro-KeyWrap': GostKeyWrapAlgorithm,
})

const GostKeyAgreementAlgorithm = Algorithm(KeyWrapAlgorithmIdentifier, {
  encode: function (value) {
    return {
      algorithm: value.id,
      parameters: value.wrapping,
    }
  },
  decode: function (value) {
    const algorithm = expand(algorithms[value.algorithm])
    algorithm.wrapping = value.parameters
    return algorithm
  },
})

const BaseEncryptionAlgorithmIdentifier = AlgorithmIdentifier({
  'id-sc-gost28147-gfb': SCGostAlgorithm,
  'id-Gost28147-89': Gost2814789Algorithm,
})

const MessageAuthenticationCodeAlgorithm = AlgorithmIdentifier({
  'id-Gost28147-89-MAC': Gost2814789Parameters,
  'id-HMACGostR3411-94': Gost341194DigestAlgorithm,
  'id-tc26-hmac-gost-3411-12-256': Gost341194DigestAlgorithm,
  'id-tc26-hmac-gost-3411-12-512': Gost341194DigestAlgorithm,
  'hmacWithSHA1': AlgorithmWithNoParam,
  'hmacWithSHA224': AlgorithmWithNoParam,
  'hmacWithSHA256': AlgorithmWithNoParam,
  'hmacWithSHA384': AlgorithmWithNoParam,
  'hmacWithSHA512': AlgorithmWithNoParam,
  'id-sc-gost28147-mac': AlgorithmWithNoParam,
  'id-sc-hmacWithGostR3411': AlgorithmWithNoParam,
})

// rfc2898 PKCS #5: Password-Based Cryptography Specification
// PBKDF2
const PBKDF2params = SEQUENCE({
  salt: CHOICE({
    specified: OCTET_STRING,
    otherSource: AlgorithmIdentifier,
  }, function (value) {
    return isBinary(value) ? 'specified' : 'otherSource'
  }),
  iterationCount: INTEGER,
  keyLength: OPTIONAL(INTEGER),
  prf: MessageAuthenticationCodeAlgorithm,
})

const PBKDF2Algorithm = Algorithm(PBKDF2params, {
  encode: function (value) {
    return {
      algorithm: value.id,
      parameters: {
        salt: value.salt,
        iterationCount: value.iterations,
        prf: value.hmac,
      },
    }
  },
  decode: function (value) {
    const algorithm = expand(algorithms[value.algorithm])
    algorithm.salt = value.parameters.salt
    algorithm.iterations = value.parameters.iterationCount
    algorithm.hmac = value.parameters.prf
    algorithm.hash = algorithm.hmac.hash
    return algorithm
  },
})

const KeyDerivationAlgorithmIdentifier = AlgorithmIdentifier({
  'PBKDF2': PBKDF2Algorithm,
})

const PBEParameter = SEQUENCE({
  salt: OCTET_STRING,
  iterationCount: INTEGER,
})

const PBES1Algorithm = Algorithm(PBEParameter, {
  paramType: PBEParameter,
  encode: function (value) {
    return {
      algorithm: value.id,
      parameters: {
        salt: value.derivation.salt,
        iterationCount: value.derivation.iterations,
      },
    }
  },
  decode: function (value) {
    const algorithm = expand(algorithms[value.algorithm])
    algorithm.derivation = expand(algorithm.derivation,
      { salt: value.parameters.salt, iterations: value.parameters.iterationCount })
    return algorithm
  },
})

// PBES2
const PBES2params = SEQUENCE({
  keyDerivationFunc: KeyDerivationAlgorithmIdentifier, // {{PBES2-KDFs}},
  encryptionScheme: BaseEncryptionAlgorithmIdentifier,
}) // {{PBES2-Encs}}

const PBES2Algorithm = Algorithm(PBES2params, {
  encode: function (value) {
    return {
      algorithm: value.id,
      parameters: {
        keyDerivationFunc: value.derivation,
        encryptionScheme: value.encryption,
      },
    }
  },
  decode: function (value) {
    const algorithm = expand(algorithms[value.algorithm])
    algorithm.derivation = value.parameters.keyDerivationFunc
    algorithm.encryption = value.parameters.encryptionScheme
    return algorithm
  },
})

const PasswordEncryptionAlgorithmIndentifier = AlgorithmIdentifier({
  // PBES1
  'pbeWithSHAAndAES128-CBC': PBES1Algorithm,
  'pbeWithSHAAndAES192-CBC': PBES1Algorithm,
  'pbeWithSHAAndAES256-CBC': PBES1Algorithm,
  'pbeWithSHA256AndAES128-CBC': PBES1Algorithm,
  'pbeWithSHA256AndAES192-CBC': PBES1Algorithm,
  'pbeWithSHA256AndAES256-CBC': PBES1Algorithm,
  'id-sc-pbeWithGost3411AndGost28147': PBES1Algorithm,
  'id-sc-pbeWithGost3411AndGost28147CFB': PBES1Algorithm,
  // PKCS12 PBES1
  'pbeWithSHAAnd3-KeyTripleDES-CBC': PBES1Algorithm,
  'pbeWithSHAAnd2-KeyTripleDES-CBC': PBES1Algorithm,
  'pbeWithSHAAnd128BitRC2-CBC': PBES1Algorithm,
  'pbeWithSHAAnd40BitRC2-CBC': PBES1Algorithm,
  'pbeUnknownGost': PBES1Algorithm,
  // PBES2
  'PBES2': PBES2Algorithm,
})

const KeyEncryptionAlgorithmIdentifier = AlgorithmIdentifier({
  ecdsa: ECDHKeyAlgorithm,
  rsaEncryption: AlgorithmWithNullParam,
  // Base encryption
  'id-sc-gost28147-gfb': SCGostAlgorithm,
  'id-Gost28147-89': Gost2814789Algorithm,
  // Key transport algorithms
  'id-sc-gostR3410-2001': ECDHKeyAlgorithm,
  'id-GostR3410-2001': GostKeyAlgorithm,
  'id-GostR3410-94': GostKeyAlgorithm,
  'id-tc26-gost3410-12-256': GostKeyAlgorithm,
  'id-tc26-gost3410-12-512': GostKeyAlgorithm,
  // Key agreement algorithms
  'id-GostR3410-94-CryptoPro-ESDH': GostKeyAgreementAlgorithm,
  'id-GostR3410-2001-CryptoPro-ESDH': GostKeyAgreementAlgorithm,
  'id-tc26-agreement-gost-3410-12-256': GostKeyAgreementAlgorithm,
  'id-tc26-agreement-gost-3410-12-512': GostKeyAgreementAlgorithm,
  'id-sc-r3410-ESDH-r3411kdf': AlgorithmWithNullParam,
  // Key encryption key algorithms
  'id-Gost28147-89-None-KeyWrap': GostKeyWrapAlgorithm, // Add ukm to algorithm
  'id-Gost28147-89-CryptoPro-KeyWrap': GostKeyWrapAlgorithm,
  'id-sc-cmsGostWrap': AlgorithmWithNoParam, // SC don't use ukm
  'id-sc-cmsGost28147Wrap': AlgorithmWithNoParam,
  // Password based encryption
  'pbeWithSHAAndAES128-CBC': PBES1Algorithm,
  'pbeWithSHAAndAES192-CBC': PBES1Algorithm,
  'pbeWithSHAAndAES256-CBC': PBES1Algorithm,
  'pbeWithSHA256AndAES128-CBC': PBES1Algorithm,
  'pbeWithSHA256AndAES192-CBC': PBES1Algorithm,
  'pbeWithSHA256AndAES256-CBC': PBES1Algorithm,
  'id-sc-pbeWithGost3411AndGost28147': PBES1Algorithm,
  'id-sc-pbeWithGost3411AndGost28147CFB': PBES1Algorithm,
  // PKCS12 PBES1
  'pbeWithSHAAnd3-KeyTripleDES-CBC': PBES1Algorithm,
  'pbeWithSHAAnd2-KeyTripleDES-CBC': PBES1Algorithm,
  'pbeWithSHAAnd128BitRC2-CBC': PBES1Algorithm,
  'pbeWithSHAAnd40BitRC2-CBC': PBES1Algorithm,
  'pbeUnknownGost': PBES1Algorithm,
  // PBES2
  'PBES2': PBES2Algorithm,
})

const PBMAC1params = SEQUENCE({
  keyDerivationFunc: KeyDerivationAlgorithmIdentifier, // {{PBMAC1-KDFs}},
  messageAuthScheme: MessageAuthenticationCodeAlgorithm,
}) // {{PBMAC1-MACs}}

const PasswordMACAlgorithm = Algorithm(PBMAC1params, {
  encode: function (value) {
    return {
      algorithm: value.id,
      parameters: {
        keyDerivationFunc: value.derivation,
        messageAuthScheme: value.hmac,
      },
    }
  },
  decode: function (value) {
    const algorithm = expand(algorithms[value.algorithm])
    algorithm.derivation = value.parameters.keyDerivationFunc
    algorithm.hmac = value.parameters.messageAuthScheme
    return algorithm
  },
})

const PasswordMACAlgorithmIdentifier = AlgorithmIdentifier({
  'PBMAC1': PasswordMACAlgorithm,
})

const ContentEncryptionAlgorithmIdentifier = AlgorithmIdentifier({
  // Base encryption
  'id-sc-gost28147-gfb': SCGostAlgorithm,
  'id-Gost28147-89': Gost2814789Algorithm,
  // Password based encryption
  'pbeWithSHAAndAES128-CBC': PBES1Algorithm,
  'pbeWithSHAAndAES192-CBC': PBES1Algorithm,
  'pbeWithSHAAndAES256-CBC': PBES1Algorithm,
  'pbeWithSHA256AndAES128-CBC': PBES1Algorithm,
  'pbeWithSHA256AndAES192-CBC': PBES1Algorithm,
  'pbeWithSHA256AndAES256-CBC': PBES1Algorithm,
  'id-sc-pbeWithGost3411AndGost28147': PBES1Algorithm,
  'id-sc-pbeWithGost3411AndGost28147CFB': PBES1Algorithm,
  // PKCS12 PBES1
  'pbeWithSHAAnd3-KeyTripleDES-CBC': PBES1Algorithm,
  'pbeWithSHAAnd2-KeyTripleDES-CBC': PBES1Algorithm,
  'pbeWithSHAAnd128BitRC2-CBC': PBES1Algorithm,
  'pbeWithSHAAnd40BitRC2-CBC': PBES1Algorithm,
  'pbeUnknownGost': PBES1Algorithm,
  // PBES2
  'PBES2': PBES2Algorithm,
})

// </editor-fold>

/*
 * Public Key Info
 *
 * http://tools.ietf.org/html/rfc5280
 *
 */ // <editor-fold defaultstate="collapsed">

const KeyData = ENCLOSURE

const DHPublicKey = KeyData(BIT_STRING(ENCAPSULATES(INTEGER)), {
  encode: function (value) {
    return Int16.encode(swapBytes(value))
  },
  decode: function (value) {
    return swapBytes(Int16.decode(value))
  },
})

const ECDHPublicKey = KeyData(BIT_STRING(ENCAPSULATES(OCTET_STRING)), {
  encode: function (value) {
    const r = new Uint8Array(value.byteLength + 1),
      d = swapBytes(value),
      len = value.byteLength / 2
    r[0] = 0x04 // type hex;
    r.set(new Uint8Array(d, len, len), 1) // x
    r.set(new Uint8Array(d, 0, len), len + 1) // y
    return r.buffer
  },
  decode: function (value) {
    assert((value.byteLength & 1) === 0)
    const d = new Uint8Array(value.byteLength - 1),
      len = d.byteLength / 2
    d.set(new Uint8Array(value, len + 1, len), 0) // y
    d.set(new Uint8Array(value, 1, len), len) // x
    return swapBytes(d)
  },
})

const GostR3410PublicKey = BIT_STRING(ENCAPSULATES(OCTET_STRING))

/**
 * Subject Public Key Info Syntax X.509
 * <pre>
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *      algorithm            AlgorithmIdentifier,
 *      subjectPublicKey     BIT STRING  }
 *
 *  AlgorithmIdentifier  ::=  SEQUENCE  {
 *      algorithm               OBJECT IDENTIFIER,
 *      parameters              ANY DEFINED BY algorithm OPTIONAL  }
 -- contains a value of the type
 -- registered for use with the
 -- algorithm object identifier value
 * </pre>
 * RFC 5280 references {@link http://tools.ietf.org/html/rfc5280}
 * @class GostASN1.SubjectPublicKeyInfo
 * @extends GostASN1.Sequence
 * @property {AlgorithmIdentifier} algorithm Identifies the public-key algorithm.
 * @property {CryptoOperationData} subjectPublicKey An binary data whose contents are the value of the public key
 */
const SubjectPublicKeyInfo = SEQUENCE({
  algorithm: KeyAlgorithmIdentifier,
  subjectPublicKey: BIT_STRING,
}, 'PUBLIC KEY')

const GostSubjectPublicKeyInfo = (function (PKTypes) {

  /**
     * Coding methods for {@link Algorithm} and {@link GostASN1.SubjectPublicKeyInfo}
     * Supported types for GOST algorithms:
     * <pre>
     *  {
     *      'id-sc-gostR3410-2001': ECDHPublicKey,
     *      'id-sc-gostR3410-94': DHPublicKey,
     *      'id-GostR3410-2001': GostR3410PublicKey,
     *      'id-GostR3410-94': GostR3410PublicKey,
     *      'id-tc26-gost3410-12-256': GostR3410PublicKey,
     *      'id-tc26-gost3410-12-512': GostR3410PublicKey
     *  }
     * </pre>
     *
     * @class GostASN1.GostSubjectPublicKeyInfo
     * @extends GostASN1.SubjectPublicKeyInfo
     * @extends Key
     */
  return ENCLOSURE(ATTRIBUTE({
    algorithm: KeyAlgorithmIdentifier,
    subjectPublicKey: ANY,
  },
  'algorithm', 'subjectPublicKey')(function (algorithm) {
    return PKTypes[algorithm.id]
  }), {
    encode: function (value) {
      return {
        algorithm: value.algorithm,
        subjectPublicKey: value.buffer,
      }
    },
    decode: function (value) {
      return {
        algorithm: value.algorithm,
        type: 'public',
        extractable: true,
        usages: ['verify', 'deriveKey', 'deriveBits'],
        buffer: value.subjectPublicKey,
      }
    },
  })
})({
  'id-sc-gostR3410-2001': ECDHPublicKey,
  'id-sc-gostR3410-94': DHPublicKey,
  'id-GostR3410-2001': GostR3410PublicKey,
  'id-GostR3410-94': GostR3410PublicKey,
  'id-tc26-gost3410-12-256': GostR3410PublicKey,
  'id-tc26-gost3410-12-512': GostR3410PublicKey,
})
// </editor-fold>

/*
 * Private Key Info PKCS#8
 *
 * http://tools.ietf.org/html/rfc5208
 *
 */ // <editor-fold defaultstate="collapsed">

const PrivateKey = OCTET_STRING

const DHPrivateKey = KeyData(PrivateKey(ENCAPSULATES(INTEGER)), {
  encode: function (value) { // for SignalCom INTEGER d
    return SInt.encode(value, true)
  },
  decode: function (value) {
    return SInt.decode(value, true)
  },
})

const GostR3410KeyValueMask = OCTET_STRING

const GostR3410KeyValueInfo = SEQUENCE({
  keyValueMask: GostR3410KeyValueMask,
  keyValyePublicKey: OCTET_STRING,
})

const GostR3410PrivateKey = CHOICE({
  privateKey: PrivateKey(ENCAPSULATES(CHOICE({
    keyValueMask: GostR3410KeyValueMask,
    keyValueInfo: GostR3410KeyValueInfo,
  }, function (value) {
    if (isBinary(value)) {return 'keyValueMask'}
    return 'keyValueInfo'
  }))),
  keyValueMask: GostR3410KeyValueMask,
}, function (value) {
  return value.enclosed ? 'keyValueMask' : 'privateKey'
})

const GostWrappedPrivateKey = (function (PKTypes) {

  /**
     * Gost Wrapped Private Key for SignalCom key container
     *
     * @class GostASN1.GostWrappedPrivateKey
     * @extends GostASN1.PrivateKeyInfo
     */
  return ATTRIBUTE({
    version: Version,
    privateKeyAlgorithm: KeyAlgorithmIdentifier,
    privateKeyWrapped: KeyData(PrivateKey(ENCAPSULATES(SEQUENCE({
      keyData: INTEGER,
      keyMac: INTEGER,
    }))), {
      encode: function (value) {
        const size = value.byteLength - 4
        return {
          keyData: SInt.encode(new Uint8Array(value, 0, size)),
          keyMac: SInt.encode(new Uint8Array(value, size, 4)),
        }
      },
      decode: function (value) {
        const data = SInt.decode(value.keyData),
          mac = SInt.decode(value.keyMac),
          result = new Uint8Array(data.byteLength + mac.byteLength)
        result.set(new Uint8Array(data))
        result.set(new Uint8Array(mac), data.byteLength)
        return result
      },
    }),
    attributes: ANY,
  }, 'privateKeyAlgorithm', 'attributes')(function (algorithm) {
    return OPTIONAL(CTX(0, IMPLICIT(Attributes({
      'id-sc-gostR3410-2001-publicKey': SET_OF_SINGLE(PKTypes[algorithm.id]),
    }))))
  })
})({
  // Signature keys
  'id-sc-gostR3410-2001': ECDHPublicKey,
  'id-sc-gostR3410-94': DHPublicKey,
  'id-GostR3410-2001': GostR3410PublicKey,
  'id-GostR3410-94': GostR3410PublicKey,
  'id-GostR3410-2001DH': GostR3410PublicKey,
  'id-GostR3410-94DH': GostR3410PublicKey,
  'id-tc26-gost3410-12-256': GostR3410PublicKey,
  'id-tc26-gost3410-12-512': GostR3410PublicKey,
  'id-tc26-agreement-gost-3410-12-256': GostR3410PublicKey,
  'id-tc26-agreement-gost-3410-12-512': GostR3410PublicKey,
})

/**
 * Private-Key Information Syntax PKSC#8
 * <pre>
 *  -- Private-key information syntax
 *
 *  PrivateKeyInfo ::= SEQUENCE {
 *      version Version,
 *      privateKeyAlgorithm AlgorithmIdentifier {{PrivateKeyAlgorithms}},
 *      privateKey PrivateKey,
 *      attributes [0] Attributes OPTIONAL }
 *
 *  Version ::= INTEGER {v1(0)} (v1,...)
 *
 *  PrivateKey ::= OCTET STRING
 *
 *  Attributes ::= SET OF Attribute
 * </pre>
 * RFC 5208 references {@link http://tools.ietf.org/html/rfc5208}
 * @class GostASN1.PrivateKeyInfo
 * @extends GostASN1.Sequence
 * @property {number} version The syntax version number. Should be 0
 * @property {AlgorithmIndentifier} privateKeyAlgorithm Identifies the private-key algorithm
 * @property {CryptoOperationData} privateKey Is an binary data whose contents are the value of the private key.
 * @property {GostASN1.Attributes} attributes A set of attributes
 */
const PrivateKeyInfo = SEQUENCE({
  version: Version,
  privateKeyAlgorithm: KeyAlgorithmIdentifier,
  privateKey: PrivateKey,
  attributes: OPTIONAL(CTX(0, IMPLICIT(Attributes))),
}, 'PRIVATE KEY')

const PrivateKeyAlgorithmIdentifier = KeyAlgorithmIdentifier

const PublicKey = BIT_STRING

const OneAsymmetricKey = SEQUENCE({
  version: Version,
  privateKeyAlgorithm: PrivateKeyAlgorithmIdentifier,
  privateKey: PrivateKey,
  attributes: OPTIONAL(CTX(0, IMPLICIT(Attributes))),
  publicKey: OPTIONAL(CTX(1, IMPLICIT(PublicKey))),
})

const AsymmetricKeyPackage = SEQUENCE_OF(OneAsymmetricKey)

const GostPrivateKeyInfo = (function (PKTypes) {

  /**
     * Coding methods for {@link Algorithm} and {@link GostASN1.PrivateKeyInfo}
     * Supported types for GOST algorithms:
     * <pre>
     *  {
     *      'id-sc-gostR3410-2001': DHPrivateKey,
     *      'id-sc-gostR3410-94': DHPrivateKey,
     *      'id-GostR3410-2001': GostR3410PrivateKey,
     *      'id-GostR3410-94': GostR3410PrivateKey,
     *      'id-tc26-gost3410-12-256': GostR3410PrivateKey,
     *      'id-tc26-gost3410-12-512': GostR3410PrivateKey
     *  }
     * </pre>
     *
     * @class GostASN1.GostPrivateKeyInfo
     * @extends GostASN1.PrivateKeyInfo
     * @extends Key
     */
  return ENCLOSURE(ATTRIBUTE({
    version: Version,
    privateKeyAlgorithm: KeyAlgorithmIdentifier,
    privateKey: ANY,
    attributes: OPTIONAL(CTX(0, IMPLICIT(Attributes))),
  },
  'privateKeyAlgorithm', 'privateKey')(function (algorithm) {
    return PKTypes[algorithm.id]
  }), {
    encode: function (value) {
      return {
        version: 0,
        privateKeyAlgorithm: value.algorithm,
        privateKey: value.buffer,
      }
    },
    decode: function (value) {
      return {
        algorithm: value.privateKeyAlgorithm,
        type: 'private',
        extractable: true,
        usages: ['sign', 'deriveKey', 'deriveBits'],
        buffer: isBinary(value.privateKey) ? value.privateKey :
          value.privateKey.keyValueMask,
      }
    },
  })
})({
  // Signature keys
  'id-sc-gostR3410-2001': DHPrivateKey,
  'id-sc-gostR3410-94': DHPrivateKey,
  'id-GostR3410-2001': GostR3410PrivateKey,
  'id-GostR3410-94': GostR3410PrivateKey,
  'id-GostR3410-2001DH': GostR3410PrivateKey,
  'id-GostR3410-94DH': GostR3410PrivateKey,
  'id-tc26-gost3410-12-256': GostR3410PrivateKey,
  'id-tc26-gost3410-12-512': GostR3410PrivateKey,
  'id-tc26-agreement-gost-3410-12-256': GostR3410PrivateKey,
  'id-tc26-agreement-gost-3410-12-512': GostR3410PrivateKey,
})

const KeyEncryptedData = OCTET_STRING
/**
 * Encrypted Private-Key Information Syntax
 * <pre>
 *  -- Encrypted private-key information syntax
 *
 *  EncryptedPrivateKeyInfo ::= SEQUENCE {
 *      encryptionAlgorithm AlgorithmIdentifier {{KeyEncryptionAlgorithms}},
 *      encryptedData KeyEncryptedData
 *  }
 *
 *  KeyEncryptedData ::= OCTET STRING
 *
 *  PrivateKeyAlgorithms ALGORITHM-IDENTIFIER ::= {
 *      ... -- For local profiles
 *  }
 *
 *  KeyEncryptionAlgorithms ALGORITHM-IDENTIFIER ::= {
 *      ... -- For local profiles
 *  }
 * </pre>
 * RFC 5208 references {@link http://tools.ietf.org/html/rfc5208}
 * @class GostASN1.EncryptedPrivateKeyInfo
 * @extends GostASN1.Sequence
 * @property {AlgorithmIdentifier} encryptionAlgorithm Identifies key encryption algorithm
 * @property {CryptoOperationData} encryptedData Encrypted {@link GostASN1.PrivateKeyInfo}
 */
const EncryptedPrivateKeyInfo = SEQUENCE({
  encryptionAlgorithm: KeyEncryptionAlgorithmIdentifier,
  encryptedData: KeyEncryptedData,
}, 'ENCRYPTED PRIVATE KEY')
// </editor-fold>

/*
 * Certificate Extensions
 *
 * http://tools.ietf.org/html/rfc5280
 *
 */ // <editor-fold defaultstate="collapsed">
const UniqueIdentifier = BIT_STRING

const CertificateSerialNumber = INTEGER

const BasicConstraints = SEQUENCE({
  cA: DEFAULT(BOOLEAN, false),
  pathLenConstraint: OPTIONAL(INTEGER),
})

const KeyUsage = BIT_STRING({
  digitalSignature: 0,
  nonRepudiation: 1,
  keyEncipherment: 2,
  dataEncipherment: 3,
  keyAgreement: 4,
  keyCertSign: 5,
  cRLSign: 6,
  encipherOnly: 7,
  decipherOnly: 8,
})
const KeyPurposeId = OBJECT_IDENTIFIER,
  ExtKeyUsageSyntax = SEQUENCE_OF(KeyPurposeId)

const KeyIdentifier = OCTET_STRING

const OtherName = SEQUENCE({
  type: OBJECT_IDENTIFIER,
  value: CTX(0, EXPLICIT(ANY)),
})

const EDIPartyName = SEQUENCE({
  nameAssigner: OPTIONAL(CTX(0, IMPLICIT(DirectoryString))),
  partyName: OPTIONAL(CTX(1, IMPLICIT(DirectoryString))),
})

const ORAddress = SEQUENCE({})

const GeneralName = CHOICE({
  otherName: CTX(0, IMPLICIT(OtherName)),
  rfc822Name: CTX(1, IMPLICIT(DirectoryString)),
  dNSName: CTX(2, IMPLICIT(DirectoryString)),
  x400Address: CTX(3, IMPLICIT(ORAddress)),
  directoryName: CTX(4, EXPLICIT(Name)), // Name is CHOICE(RDNSequence)
  ediPartyName: CTX(5, IMPLICIT(EDIPartyName)),
  uniformResourceIdentifier: CTX(6, IMPLICIT(DirectoryString)),
  iPAddress: CTX(7, IMPLICIT(OCTET_STRING)),
  registeredID: CTX(8, IMPLICIT(OBJECT_IDENTIFIER)),
}, function (value) {
  return typeof value === 'string' || value instanceof String ?
    (value.indexOf('@') >= 0 ? 'rfc822Name' : 'dNSName') :
    isBinary(value) ? 'iPAddress' : 'directoryName'
})

const GeneralNames = SEQUENCE_OF(GeneralName)

const AuthorityKeyIdentifier = SEQUENCE({
  keyIdentifier: OPTIONAL(CTX(0, IMPLICIT(KeyIdentifier))),
  authorityCertIssuer: OPTIONAL(CTX(1, IMPLICIT(GeneralNames))),
  authorityCertSerialNumber: OPTIONAL(CTX(2, IMPLICIT(CertificateSerialNumber))),
})

const PrivateKeyUsagePeriod = SEQUENCE({
  notBefore: OPTIONAL(CTX(0, IMPLICIT(GeneralizedTime))),
  notAfter: OPTIONAL(CTX(1, IMPLICIT(GeneralizedTime))),
})

const CertPolicyId = OBJECT_IDENTIFIER,
  PolicyQualifierId = OBJECT_IDENTIFIER

const PolicyQualifierInfo = SEQUENCE({
  policyQualifierId: PolicyQualifierId,
  qualifier: ANY,
})

const PolicyInformation = SEQUENCE({
  policyIdentifier: CertPolicyId,
  policyQualifiers: OPTIONAL(SEQUENCE_OF(PolicyQualifierInfo)),
})

const PolicyMapping = SEQUENCE({
  issuerDomainPolicy: CertPolicyId,
  subjectDomainPolicy: CertPolicyId,
})

const BaseDistance = INTEGER

const GeneralSubtree = SEQUENCE({
  base: GeneralName,
  minimum: DEFAULT(CTX(0, IMPLICIT(BaseDistance)), 0),
  maximum: OPTIONAL(CTX(1, IMPLICIT(BaseDistance))),
})

const GeneralSubtrees = SEQUENCE_OF(GeneralSubtree)

const NameConstraints = SEQUENCE({
  permittedSubtrees: OPTIONAL(CTX(0, IMPLICIT(GeneralSubtrees))),
  excludedSubtrees: OPTIONAL(CTX(1, IMPLICIT(GeneralSubtrees))),
})

const SkipCerts = INTEGER

const PolicyConstraints = SEQUENCE({
  requireExplicitPolicy: OPTIONAL(CTX(0, IMPLICIT(SkipCerts))),
  inhibitPolicyMapping: OPTIONAL(CTX(1, IMPLICIT(SkipCerts))),
})

const ReasonFlags = BIT_STRING({
  unused: 0,
  keyCompromise: 1,
  cACompromise: 2,
  affiliationChanged: 3,
  superseded: 4,
  cessationOfOperation: 5,
  certificateHold: 6,
  privilegeWithdrawn: 7,
  aACompromise: 8,
})

const DistributionPointName = CHOICE({
  fullName: CTX(0, IMPLICIT(GeneralNames)),
  nameRelativeToCRLIssuer: CTX(1, IMPLICIT(RelativeDistinguishedName)),
}, function (value) {
  return value instanceof Array ? 'fullName' : 'nameRelativeToCRLIssuer'
})

const DistributionPoint = SEQUENCE({
  distributionPoint: OPTIONAL(CTX(0, EXPLICIT(DistributionPointName))), // DistributionPointName CHOICE
  reasons: OPTIONAL(CTX(1, IMPLICIT(ReasonFlags))),
  cRLIssuer: OPTIONAL(CTX(2, IMPLICIT(GeneralNames))),
})

const CRLDistributionPoints = SEQUENCE_OF(DistributionPoint)

const FreshestCRL = CRLDistributionPoints

const AccessDescription = SEQUENCE({
  accessMethod: OBJECT_IDENTIFIER,
  accessLocation: GeneralName,
})

const Extension = function (typeSet, defaultCritical) {

  const Attribute = ATTRIBUTE({
    extnID: OBJECT_IDENTIFIER,
    critical: DEFAULT(BOOLEAN, false),
    extnValue: function (type) {
      return OCTET_STRING(ENCAPSULATES(type))
    },
  }, 'extnID', 'extnValue')

  var Class = extend(Attribute(typeSet), {
    object: {
      get: function () {
        const value = this._get(Class.super, 'object')
        if (value && typeof value.extnValue === 'object') {this.defineValue(value.extnValue)}
        return value
      },
      set: function (object) {
        this._set(Class.super, 'object', object)
        // Define critical
        if (object && object.extnValue) {
          if (object.extnValue.critical !== undefined) {this.critical = object.extnValue.critical} else if (this.critical === undefined && defaultCritical) {this.critical = defaultCritical(this.extnID, object.extnValue)}
        }
      },
    },
    extnValue: {
      get: function () {
        // Get value property of object
        const value = this._get(Class.super, 'extnValue')
        if (typeof value === 'object') {this.defineValue(value)}
        return value
      },
      set: function (object) {
        // Set value property of object
        this._set(Class.super, 'extnValue', object)
        // Define critical
        if (object) {
          if (object.critical !== undefined) {this.critical = object.critical} else if (this.critical === undefined && defaultCritical) {this.critical = defaultCritical(this.extnID, object)}
        }
      },
    },
    defineValue: function (value) {
      if (typeof value === 'object') {
        if (!getOwnPropertyDescriptor(value, 'critical')) {
          const self = this
          defineProperty(value, 'critical', {
            get: function () {
              return self.critical
            },
            set: function (value) {
              self.critical = value
            },
            enumerable: true,
            configurable: false,
          })
        }
      }
    },
  })
  return Class
}

// http://base.garant.ru/70133464/#ixzz4KaOTGI1l
const IssuerSignTool = SEQUENCE({
  signTool: UTF8String,
  cATool: UTF8String,
  signToolCert: UTF8String,
  cAToolCert: UTF8String,
})

/**
 * Extensions is a base class for extension attributes of certificates, CRLs, requests and etc.
 *
 * @class GostASN1.Extensions
 * @extends GostASN1.Set
 */
const Extensions = SEQUENCE_OF(Extension, {
  typeName: 'extnID',
  valueName: 'extnValue',
})

const CertExtensions = Extensions({
  authorityKeyIdentifier: AuthorityKeyIdentifier,
  subjectKeyIdentifier: KeyIdentifier,
  keyUsage: KeyUsage,
  privateKeyUsagePeriod: PrivateKeyUsagePeriod,
  certificatePolicies: SEQUENCE_OF(PolicyInformation),
  policyMappings: SEQUENCE_OF(PolicyMapping),
  subjectAltName: GeneralNames,
  issuerAltName: GeneralNames,
  subjectDirectoryAttributes: AttributeSequence,
  basicConstraints: BasicConstraints,
  nameConstraints: NameConstraints,
  policyConstraints: PolicyConstraints,
  extKeyUsage: ExtKeyUsageSyntax,
  cRLDistributionPoints: CRLDistributionPoints,
  inhibitAnyPolicy: SkipCerts,
  freshestCRL: FreshestCRL,
  authorityInfoAccess: SEQUENCE_OF(AccessDescription),
  subjectInfoAccess: SEQUENCE_OF(AccessDescription),
  subjectSignTool: UTF8String,
  issuerSignTool: IssuerSignTool,
}, function (id, value) {
  return id === 'keyUsage' ||
        (id === 'basicConstraints' && value.pathLenConstraint === undefined)
})
// </editor-fold>

/*
 * Signature Values
 *
 * http://tools.ietf.org/html/rfc5280
 * http://tools.ietf.org/html/rfc4491
 *
 */ // <editor-fold defaultstate="collapsed">

/**
 * Gost Signature encode signature values for different GOST signatures
 * Support algorithms:
 * <pre>
 *  {
 *      'id-GostR3410-94': GostR3410Signature,
 *      'id-GostR3410-2001': GostR3410Signature,
 *      'id-tc26-gost3410-12-256': GostR3410Signature,
 *      'id-tc26-gost3410-12-512': GostR3410Signature,
 *      'id-GostR3411-94-with-GostR3410-2001': GostR3410Signature,
 *      'id-GostR3411-94-with-GostR3410-94': GostR3410Signature,
 *      'id-tc26-signwithdigest-gost3410-12-94': GostR3410Signature,
 *      'id-tc26-signwithdigest-gost3410-12-256': GostR3410Signature,
 *      'id-tc26-signwithdigest-gost3410-12-512': GostR3410Signature,
 *      'id-sc-gostR3410-94': ECDHSignature,
 *      'id-sc-gostR3410-2001': ECDHSignature,
 *      'id-sc-gostR3411-94-with-gostR3410-94': ECDHSignature,
 *      'id-sc-gostR3411-94-with-gostR3410-2001': ECDHSignature
 *  }
 * </pre>
 *
 * @class GostASN1.GostSignature
 * @extends GostASN1.Sequence
 */

// SignalCom signature
const ECDHSignature = SEQUENCE({
  r: INTEGER,
  s: INTEGER,
})

const GostR3410Signature = ANY

// Signature value (only need for CryptoPro
//    var GostSignature = extend(CHOICE({
//        ecdhSignature: ECDHSignature}, 'ecdhSignature'));
const GostSignature = ECDHSignature

// </editor-fold>

/*
 * Certificate
 *
 * http://tools.ietf.org/html/rfc5280
 *
 */ // <editor-fold defaultstate="collapsed">

/**
 * The sequence TBSCertificate contains information associated with the
 * subject of the certificate and the CA who issued it.  Every
 * TBSCertificate contains the names of the subject and issuer, a public
 * key associated with the subject, a validity period, a version number,
 * and a serial number; some MAY contain optional unique identifier
 * fields.  The remainder of this section describes the syntax and
 * semantics of these fields.  A TBSCertificate usually includes
 * extensions.
 * <pre>
 *  TBSCertificate  ::=  SEQUENCE  {
 *       version         [0]  EXPLICIT Version DEFAULT v1,
 *       serialNumber         CertificateSerialNumber,
 *       signature            AlgorithmIdentifier,
 *       issuer               Name,
 *       validity             Validity,
 *       subject              Name,
 *       subjectPublicKeyInfo SubjectPublicKeyInfo,
 *       issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                            -- If present, version MUST be v2 or v3
 *       subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
 *                            -- If present, version MUST be v2 or v3
 *       extensions      [3]  EXPLICIT Extensions OPTIONAL
 *                            -- If present, version MUST be v3
 *       }
 *
 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 *
 *  CertificateSerialNumber  ::=  INTEGER
 *
 *  Validity ::= SEQUENCE {
 *       notBefore      Time,
 *       notAfter       Time }
 *
 *  Time ::= CHOICE {
 *       utcTime        UTCTime,
 *       generalTime    GeneralizedTime }
 *
 *  UniqueIdentifier  ::=  BIT STRING
 *
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {
 *       algorithm            AlgorithmIdentifier,
 *       subjectPublicKey     BIT STRING  }
 *
 *  Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
 *
 *  Extension  ::=  SEQUENCE  {
 *       extnID      OBJECT IDENTIFIER,
 *       critical    BOOLEAN DEFAULT FALSE,
 *       extnValue   OCTET STRING  }
 * </pre>
 * See {@link GostASN1.Certificate} and {@link GostASN1.SubjectPublicKeyInfo}<br><br>
 * RFC 5280 references {@link http://tools.ietf.org/html/rfc5280}
 *
 * @class GostASN1.TBSCertificate
 * @extends GostASN1.Sequence
 * @extends GostASN1.Validity
 * @property {number} version The version of the encoded certificate
 * @property {(number|string)} serialNumber The serial number MUST be a positive integer assigned by the CA to each certificate.
 * @property {AlgorithmIdentifier} signature The algorithm identifier for the algorithm used by the CA to sign the certificate.
 * @property {GostASN1.Name} issuer The issuer field identifies the entity that has signed and issued the certificate.
 * @property {GostASN1.Validity} validity The certificate validity period
 * @property {GostASN1.Name} subject The subject field identifies the entity associated with the public key stored in the subject public key field.
 * @property {GostASN1.SubjectPublicKeyInfo} subject The public key and identify the algorithm with which the key is used
 * @property {CryptoOperationData} issuerUniqueID The issuer unique identifier
 * @property {CryptoOperationData} subjectUniqueID The subject unique identifier
 * @property {GostASN1.Extensions} extensions The extensions defined for X.509 v3 certificates
 */
const TBSCertificate = COMBINE(SEQUENCE({
  version: CTX(0, EXPLICIT(Version)),
  serialNumber: CertificateSerialNumber,
  signature: SignatureAlgorithmIdentifier,
  issuer: Name,
  validity: Validity,
  subject: Name,
  subjectPublicKeyInfo: SubjectPublicKeyInfo,
  issuerUniqueID: OPTIONAL(CTX(1, IMPLICIT(UniqueIdentifier))), // If present, version MUST be v2 or v3
  subjectUniqueID: OPTIONAL(CTX(2, IMPLICIT(UniqueIdentifier))), // If present, version MUST be v2 or v3
  extensions: OPTIONAL(CTX(3, EXPLICIT(CertExtensions))),
})) // If present, version MUST be v3

/**
 * The X.509 v3 certificate basic syntax is as follows.  For signature
 * calculation, the data that is to be signed is encoded using the ASN.1
 * distinguished encoding rules (DER) [X.690].  ASN.1 DER encoding is a
 * tag, length, value encoding system for each element.
 * <pre>
 *  Certificate  ::=  SEQUENCE  {
 *       tbsCertificate       TBSCertificate,
 *       signatureAlgorithm   AlgorithmIdentifier,
 *       signatureValue       BIT STRING  }
 * </pre>
 * See {@link GostASN1.TBSCertificate}<br><br>
 * RFC 5280 references {@link http://tools.ietf.org/html/rfc5280}
 *
 * @class GostASN1.Certificate
 * @extends GostASN1.TBSCertificate
 * @property {GostASN1.TBSCertificate} tbsCertificate The sequence TBSCertificate
 * @property {AlgorithmIndentifier} signatureAlgorithm Identifies signature algorithm
 * @property {CryptoOperationData} signatureValue Signature value
 */
const Certificate = SEQUENCE({
  tbsCertificate: TBSCertificate,
  signatureAlgorithm: SignatureAlgorithmIdentifier,
  signatureValue: BIT_STRING,
}, 'CERTIFICATE')
// </editor-fold>

/*
 * Certification Request
 *
 * http://tools.ietf.org/html/rfc2986
 *
 */ // <editor-fold defaultstate="collapsed">

const ExtensionRequest = CertExtensions

const CRIAttributes = Attributes({
  challengePassword: SET_OF_SINGLE(DirectoryString),
  extensionRequest: SET_OF_SINGLE(ExtensionRequest),
  msCertExtensions: SET_OF_SINGLE(CertExtensions),
  extendedCertificateAttributes: SET_OF_SINGLE(Attributes),
})

/**
 * Certification request information shall have ASN.1 type CertificationRequestInfo:
 * <pre>
 *  CertificationRequestInfo ::= SEQUENCE {
 *       version       INTEGER { v1(0) } (v1,...),
 *       subject       Name,
 *       subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
 *       attributes    [0] Attributes{{ CRIAttributes }}
 *  }
 *
 *  SubjectPublicKeyInfo { ALGORITHM : IOSet} ::= SEQUENCE {
 *       algorithm        AlgorithmIdentifier {{IOSet}},
 *       subjectPublicKey BIT STRING
 *  }
 *
 *  PKInfoAlgorithms ALGORITHM ::= {
 *       ...  -- add any locally defined algorithms here -- }
 *
 *  Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
 *
 *  CRIAttributes  ATTRIBUTE  ::= {
 *       ... -- add any locally defined attributes here -- }
 *
 *  Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
 *       type   ATTRIBUTE.&id({IOSet}),
 *       values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
 *  }
 * </pre>
 * See {@link GostASN1.CertificationRequest} and {@link GostASN1.SubjectPublicKeyInfo}<br><br>
 * RFC 2986 references {@link http://tools.ietf.org/html/rfc2986}
 *
 * @class GostASN1.CertificationRequestInfo
 * @extends GostASN1.Sequence
 * @property {number} version The version of the encoded request
 * @property {GostASN1.Name} subject The subject field identifies the entity associated with the public key stored in the subject public key field.
 * @property {GostASN1.SubjectPublicKeyInfo} subject The public key and identify the algorithm with which the key is used
 * @property {GostASN1.Attributes} attributes The request attributes
 */
const CertificationRequestInfo = COMBINE(SEQUENCE({
  version: INTEGER,
  subject: Name,
  subjectPublicKeyInfo: SubjectPublicKeyInfo,
  attributes: CTX(0, IMPLICIT(CRIAttributes)),
}))

/**
 * A certification request consists of three parts: "certification
 * request information," a signature algorithm identifier, and a digital
 * signature on the certification request information.  The
 * certification request information consists of the entity's
 * distinguished name, the entity's public key, and a set of attributes
 * providing other information about the entity.
 * <pre>
 *  A certification request shall have ASN.1 type CertificationRequest:
 *
 *  CertificationRequest ::= SEQUENCE {
 *       certificationRequestInfo CertificationRequestInfo,
 *       signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
 *       signature          BIT STRING
 *  }
 *
 *  AlgorithmIdentifier {ALGORITHM:IOSet } ::= SEQUENCE {
 *       algorithm          ALGORITHM.&id({IOSet}),
 *       parameters         ALGORITHM.&Type({IOSet}{@algorithm}) OPTIONAL
 *  }
 *
 *  SignatureAlgorithms ALGORITHM ::= {
 *       ... -- add any locally defined algorithms here -- }
 * </pre>
 * See {@link GostASN1.CertificationRequestInfo}
 * RFC 2986 references {@link http://tools.ietf.org/html/rfc2986}
 *
 * @class GostASN1.CertificationRequest
 * @extends GostASN1.CertificationRequestInfo
 * @property {GostASN1.CertificationRequestInfo} requestInfo Request information
 * @property {AlgorithmIndentifier} signatureAlgorithm Identifies signature algorithm
 * @property {CryptoOperationData} signatureValue Signature value
 */
const CertificationRequest = SEQUENCE({
  requestInfo: CertificationRequestInfo,
  signatureAlgorithm: SignatureAlgorithmIdentifier,
  signatureValue: BIT_STRING,
}, 'CERTIFICATE REQUEST')
// </editor-fold>

/*
 * Certificate Revocation List
 *
 * http://tools.ietf.org/html/rfc5280
 *
 */ // <editor-fold defaultstate="collapsed">

const CRLNumber = INTEGER

const CRLReason = ENUMERATED({
  unspecified: 0,
  keyCompromise: 1,
  cACompromise: 2,
  affiliationChanged: 3,
  superseded: 4,
  cessationOfOperation: 5,
  certificateHold: 6,
  removeFromCRL: 8,
  privilegeWithdrawn: 9,
  aACompromise: 10,
})

const IssuingDistributionPoint = SEQUENCE({
  distributionPoint: OPTIONAL(CTX(0, EXPLICIT(DistributionPointName))), // DistributionPointName is CHOICE
  onlyContainsUserCerts: DEFAULT(CTX(1, IMPLICIT(BOOLEAN)), false),
  onlyContainsCACerts: DEFAULT(CTX(2, IMPLICIT(BOOLEAN)), false),
  onlySomeReasons: OPTIONAL(CTX(3, IMPLICIT(ReasonFlags))),
  indirectCRL: DEFAULT(CTX(4, IMPLICIT(BOOLEAN)), false),
  onlyContainsAttributeCerts: DEFAULT(CTX(5, IMPLICIT(BOOLEAN)), false),
})

const CLRExtensions = Extensions({
  authorityKeyIdentifier: AuthorityKeyIdentifier,
  issuerAltName: GeneralNames,
  cRLNumber: CRLNumber,
  deltaCRLIndicator: CRLNumber,
  issuingDistributionPoint: IssuingDistributionPoint,
  freshestCRL: FreshestCRL,
}, function (id) {
  return id === 'cRLNumber'
})

const CLREntryExtensions = Extensions({
  cRLReason: CRLReason,
  instructionCode: OBJECT_IDENTIFIER,
  invalidityDate: GeneralizedTime,
  certificateIssuer: GeneralNames,
})

/**
 * This field is itself a sequence containing the name of the issuer,
 * issue date, issue date of the next list, the optional list of revoked
 * certificates, and optional CRL extensions.  When there are no revoked
 * certificates, the revoked certificates list is absent.  When one or
 * more certificates are revoked, each entry on the revoked certificate
 * list is defined by a sequence of user certificate serial number,
 * revocation date, and optional CRL entry extensions.
 * <pre>
 *  TBSCertList  ::=  SEQUENCE  {
 *       version                 Version OPTIONAL,
 *                                    -- if present, MUST be v2
 *       signature               AlgorithmIdentifier,
 *       issuer                  Name,
 *       thisUpdate              Time,
 *       nextUpdate              Time OPTIONAL,
 *       revokedCertificates     SEQUENCE OF SEQUENCE  {
 *            userCertificate         CertificateSerialNumber,
 *            revocationDate          Time,
 *            crlEntryExtensions      Extensions OPTIONAL
 *                                          -- if present, MUST be v2
 *                                 }  OPTIONAL,
 *       crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
 *                                          -- if present, MUST be v2
 *                                 }
 * </pre>
 * See {@link GostASN1.CertificateList}<br><br>
 * RFC 5280 references {@link http://tools.ietf.org/html/rfc5280}
 *
 * @class GostASN1.TBSCertList
 * @extends GostASN1.Sequence
 * @property {number} version The version of the encoded CRL
 * @property {AlgorithmIdentifier} signature The algorithm identifier for the algorithm used to sign the CRL
 * @property {Name} issuer The issuer name identifies the entity that has signed and issued the CRL
 * @property {Date} thisUpdate The issue date of this CRL
 * @property {Date} nextUpdate The date by which the next CRL will be issued
 * @property {Array} revokedCertificates The revoked certificates are listed by their serial numbers
 * @property {Extensions} crlExtensions The CRL extensions
 */
const TBSCertList = COMBINE(SEQUENCE({
  version: OPTIONAL(Version), // if present, MUST be v2
  signature: SignatureAlgorithmIdentifier,
  issuer: Name,
  thisUpdate: Time,
  nextUpdate: OPTIONAL(Time),
  revokedCertificates: OPTIONAL(SEQUENCE_OF(SEQUENCE({
    userCertificate: CertificateSerialNumber,
    revocationDate: Time,
    crlEntryExtensions: OPTIONAL(CLREntryExtensions), // if present, MUST be v2
  }))),
  crlExtensions: OPTIONAL(CTX(0, EXPLICIT(CLRExtensions))),
})) // if present, MUST be v2

/**
 * The X.509 v2 CRL syntax is as follows.  For signature calculation,
 * the data that is to be signed is ASN.1 DER encoded.  ASN.1 DER
 * encoding is a tag, length, value encoding system for each element.
 * <pre>
 *  CertificateList  ::=  SEQUENCE  {
 *       tbsCertList          TBSCertList,
 *       signatureAlgorithm   AlgorithmIdentifier,
 *       signatureValue       BIT STRING  }
 * </pre>
 * See {@link GostASN1.TBSCertList}<br><br>
 * RFC 5280 references {@link http://tools.ietf.org/html/rfc5280}
 *
 * @class GostASN1.CertificateList
 * @extends GostASN1.TBSCertList
 * @property {GostASN1.TBSCertList} tbsCertList The tbsCertList
 * @property {AlgorithmIndentifier} signatureAlgorithm Identifies signature algorithm
 * @property {CryptoOperationData} signatureValue Signature value
 */
const CertificateList = SEQUENCE({
  tbsCertList: TBSCertList,
  signatureAlgorithm: SignatureAlgorithmIdentifier,
  signatureValue: BIT_STRING,
}, 'CRL')
// </editor-fold>

/*
 * Attribute Certificate Definision
 * http://tools.ietf.org/html/rfc5755
 *
 */ // <editor-fold defaultstate="collapsed">

const AttCertVersion = INTEGER

const ObjectDigestInfo = SEQUENCE({
  digestedObjectType: ENUMERATED({
    publicKey: 0,
    publicKeyCert: 1,
    otherObjectTypes: 2,
  }), // otherObjectTypes MUST NOT be used in this profile
  otherObjectTypeID: OPTIONAL(OBJECT_IDENTIFIER),
  digestAlgorithm: DigestAlgorithmIdentifier,
  objectDigest: BIT_STRING,
})

const IssuerSerial = SEQUENCE({
  issuer: GeneralNames,
  serial: CertificateSerialNumber,
  issuerUID: OPTIONAL(UniqueIdentifier),
})

const V2Form = SEQUENCE({
  issuerName: OPTIONAL(GeneralNames),
  baseCertificateID: OPTIONAL(CTX(0, IMPLICIT(IssuerSerial))),
  // issuerName MUST be present in this profile baseCertificateID and
  // objectDigestInfo MUST NOT be present in this profile
  objectDigestInfo: OPTIONAL(CTX(1, IMPLICIT(ObjectDigestInfo))),
})

const TargetCert = SEQUENCE({
  targetCertificate: IssuerSerial,
  targetName: OPTIONAL(GeneralName),
  certDigestInfo: OPTIONAL(ObjectDigestInfo),
})

const Target = CHOICE({
  targetName: CTX(0, EXPLICIT(GeneralName)), // GeneralName is CHOICE
  targetGroup: CTX(1, EXPLICIT(GeneralName)),
  targetCert: CTX(2, IMPLICIT(TargetCert)),
})

const Targets = SEQUENCE_OF(Target)

const AttCertExtensions = Extensions({
  auditIdentity: OCTET_STRING,
  targetInformation: Targets,
  authorityKeyIdentifier: AuthorityKeyIdentifier,
  authorityInfoAccess: SEQUENCE_OF(AccessDescription),
  cRLDistributionPoints: CRLDistributionPoints,
  noRevAvail: NULL,
}, function (id) {
  return id === 'auditIdentity' || id === 'targetInformation'
})

const Holder = SEQUENCE({
  // the issuer and serial number of the holder's Public Key Certificate
  baseCertificateID: OPTIONAL(CTX(0, IMPLICIT(IssuerSerial))),
  // the name of the claimant or role
  entityName: OPTIONAL(CTX(1, IMPLICIT(GeneralNames))),
  // used to directly authenticate the holder, for example, an executable
  objectDigestInfo: OPTIONAL(CTX(2, IMPLICIT(ObjectDigestInfo))),
})

const AttCertIssuer = CHOICE({
  v1Form: GeneralNames, // MUST NOT be used in this profile
  v2Form: CTX(0, IMPLICIT(V2Form)),
}, 'v2Form') // v2 only

const AttCertValidityPeriod = SEQUENCE({
  notBeforeTime: GeneralizedTime,
  notAfterTime: GeneralizedTime,
})

const SvceAuthInfo = SEQUENCE({
  service: GeneralName,
  ident: GeneralName,
  authInfo: OPTIONAL(OCTET_STRING),
})

const RoleSyntax = SEQUENCE({
  roleAuthority: OPTIONAL(CTX(0, IMPLICIT(GeneralNames))),
  roleName: CTX(1, EXPLICIT(GeneralName)),
}) // GeneralName is CHOICE

const ClassList = BIT_STRING({
  unmarked: 0,
  unclassified: 1,
  restricted: 2,
  confidential: 3,
  secret: 4,
  topSecret: 5,
})

const SecurityCategory = SEQUENCE({
  type: CTX(0, IMPLICIT(OBJECT_IDENTIFIER)),
  value: CTX(1, IMPLICIT(ANY)),
})

const Clearance = SEQUENCE({
  policyId: CTX(0, IMPLICIT(OBJECT_IDENTIFIER)),
  classList: DEFAULT(CTX(1, IMPLICIT(ClassList)), ['unclassified']),
  securityCategories: OPTIONAL(CTX(2, IMPLICIT(SET_OF(SecurityCategory)))),
})

const IetfAttrSyntax = SEQUENCE({
  policyAuthority: OPTIONAL(CTX(0, IMPLICIT(GeneralNames))),
  values: SEQUENCE_OF(CHOICE({
    octets: OCTET_STRING,
    oid: OBJECT_IDENTIFIER,
    string: UTF8String,
  }, function (value) {
    return isBinary ? 'octets' : getIdentifier(value) ? 'oid' : 'string'
  })),
})

/**
 * X.509 Attribute Certificate Definition<br><br>
 *
 * X.509 contains the definition of an AC given below.  All types that
 * are not defined in this document can be found in [PKIXPROF].
 * <pre>
 *           AttributeCertificateInfo ::= SEQUENCE {
 *                version              AttCertVersion -- version is v2,
 *                holder               Holder,
 *                issuer               AttCertIssuer,
 *                signature            AlgorithmIdentifier,
 *                serialNumber         CertificateSerialNumber,
 *                attrCertValidityPeriod   AttCertValidityPeriod,
 *                attributes           SEQUENCE OF Attribute,
 *                issuerUniqueID       UniqueIdentifier OPTIONAL,
 *                extensions           Extensions OPTIONAL
 *           }
 * <pre>
 * RFC 3281 references {@link http://tools.ietf.org/html/rfc3281}
 *
 * @class GostASN1.AttributeCertificateInfo
 * @extends GostASN1.Sequence
 * @property {number} version The version of the encoded certificate
 * @property {GostASN1.Name} holder Identifies the holder.
 * @property {GostASN1.Name} issuer Identifies the issuer.
 * @property {AlgorithmIdentifier} signature The algorithm identifier for the algorithm used by the CA to sign the certificate.
 * @property {(number|string)} serialNumber The serial number MUST be a positive integer assigned by the CA to each certificate.
 * @property {GostASN1.Validity} attrCertValidityPeriod The certificate validity period
 * @property {GostASN1.Attributes} attributes The certificate attributes
 * @property {CryptoOperationData} issuerUniqueID The issuer unique identifier
 * @property {GostASN1.Extensions} extensions The certificate extensions
 */
const AttributeCertificateInfo = COMBINE(SEQUENCE({
  version: AttCertVersion, // version is v2,
  holder: Holder,
  issuer: AttCertIssuer,
  signature: SignatureAlgorithmIdentifier,
  serialNumber: CertificateSerialNumber,
  attrCertValidityPeriod: AttCertValidityPeriod,
  attributes: AttributeSequence({
    authenticationInfo: SET_OF(SvceAuthInfo),
    accessIdentity: SET_OF(SvceAuthInfo),
    chargingIdentity: SET_OF_SINGLE(IetfAttrSyntax),
    group: SET_OF_SINGLE(IetfAttrSyntax),
    role: SET_OF(RoleSyntax),
    clearance: SET_OF(Clearance),
  }),
  issuerUniqueID: OPTIONAL(UniqueIdentifier),
  extensions: OPTIONAL(AttCertExtensions),
}))

/**
 * Attribute Certificate Profile<br></br>
 *
 * ACs may be used in a wide range of applications and environments
 * covering a broad spectrum of interoperability goals and a broader
 * spectrum of operational and assurance requirements.  The goal of this
 * document is to establish a common baseline for generic applications
 * requiring broad interoperability and limited special purpose
 * requirements.  In particular, the emphasis will be on supporting the
 * use of attribute certificates for informal Internet electronic mail,
 * IPSec, and WWW applications.
 * <pre>
 *           AttributeCertificate ::= SEQUENCE {
 *                acinfo               AttributeCertificateInfo,
 *                signatureAlgorithm   AlgorithmIdentifier,
 *                signatureValue       BIT STRING
 *           }
 * </pre>
 * See {@link GostASN1.AttributeCertificateInfo}<br><br>
 * RFC 3281 references {@link http://tools.ietf.org/html/rfc3281}
 *
 * @class GostASN1.AttributeCertificate
 * @extends GostASN1.AttributeCertificateInfo
 * @property {GostASN1.AttributeCertificateInfo} acinfo Attribute certificate information
 * @property {AlgorithmIndentifier} signatureAlgorithm Identifies signature algorithm
 * @property {CryptoOperationData} signatureValue Signature value
 */
const AttributeCertificate = SEQUENCE({
  acinfo: AttributeCertificateInfo,
  signatureAlgorithm: SignatureAlgorithmIdentifier,
  signatureValue: BIT_STRING,
}, 'ATTRIBUTE CERTIFICATE')
// </editor-fold>

/*
 * Encrypted Key with CMS
 *
 * http://tools.ietf.org/html/rfc5652
 * http://tools.ietf.org/html/rfc4490
 *
 */ // <editor-fold defaultstate="collapsed">

// RecipientInfo
var EncryptedKey = OCTET_STRING

const EncryptedContent = OCTET_STRING

var SubjectKeyIdentifier = OCTET_STRING

const UserKeyingMaterial = OCTET_STRING

const ECCCMSSharedInfo = SEQUENCE({
  keyInfo: KeyWrapAlgorithmIdentifier,
  entityUInfo: OPTIONAL(CTX(0, EXPLICIT(OCTET_STRING))),
  suppPubInfo: CTX(2, EXPLICIT(OCTET_STRING)),
})

// GOST Key Transport & Key agreement rfc4490
const Gost2814789EncryptedKey = ENCLOSURE(SEQUENCE({
  encryptedKey: Gost2814789Key,
  maskKey: OPTIONAL(CTX(0, IMPLICIT(Gost2814789Key))),
  macKey: Gost2814789MAC,
}), {
  encode: function (value) {
    // wrappedKey: (CEK_ENC(32) | CEK_MAC(4))
    const encryptedKey = new Uint8Array(new Uint8Array(value, 0, 32)).buffer,
      macKey = new Uint8Array(new Uint8Array(value, 32, 4)).buffer
    return { // from wrapped key
      encryptedKey: encryptedKey,
      macKey: macKey,
    }
  },
  decode: function (value) {
    const encryptedKey = value.encryptedKey,
      maskKey = value.maskKey,
      macKey = value.macKey
    if (maskKey) {
      const m = new Int32Array(maskKey), k = new Int32Array(encryptedKey)
      for (let i = 0, n = m.length / k.length; i < n; i++) {
        for (let j = 0, l = k.length; j < l; j++) {k[j] = (k[j] + m[l * i + j]) & 0xffffffff}
      }
    }
    const result = new Uint8Array(encryptedKey.byteLength + macKey.byteLength)
    result.set(new Uint8Array(encryptedKey), 0)
    result.set(new Uint8Array(macKey), 32)
    return result.buffer
  },
})


const GostR3410TransportParameters = SEQUENCE({
  encryptionParamSet: Gost2814789ParamSet,
  ephemeralPublicKey: OPTIONAL(CTX(0, IMPLICIT(GostSubjectPublicKeyInfo))),
  ukm: OCTET_STRING,
}) // ( SIZE(8) )

const GostR3410KeyTransport = ENCLOSURE(SEQUENCE({
  sessionEncryptedKey: Gost2814789EncryptedKey,
  transportParameters: OPTIONAL(CTX(0, IMPLICIT(GostR3410TransportParameters))),
}), {
  encode: function (value) {
    const algorithm = value.algorithm
    return {
      sessionEncryptedKey: value.sessionEncryptedKey,
      transportParameters: {
        encryptionParamSet: attributes['sBox'][algorithm.wrapping.sBox || 'E-A'],
        ephemeralPublicKey: algorithm['public'],
        ukm: algorithm.ukm,
      },
    }
  },
  decode: function (value) {
    return {
      algorithm: {
        wrapping: parameters[value.transportParameters.encryptionParamSet],
        ukm: value.transportParameters.ukm,
        'public': value.transportParameters.ephemeralPublicKey,
      },
      sessionEncryptedKey: value.sessionEncryptedKey,
    }
  },
})

const SCGostKeyTransport = ENCLOSURE(SEQUENCE({
  sessionEncryptedKey: Gost2814789EncryptedKey,
  ukm: SEQUENCE({
    ephemeralPublicKey: GostSubjectPublicKeyInfo,
    addedukm: OPTIONAL(CTX(0, EXPLICIT(UserKeyingMaterial))),
  }),
}), {
  encode: function (value) {
    const algorithm = value.algorithm
    return {
      sessionEncryptedKey: value.sessionEncryptedKey,
      ukm: {
        ephemeralPublicKey: algorithm['public'],
        addedukm: algorithm.ukm,
      },
    }
  },
  decode: function (value) {
    return {
      algorithm: {
        ukm: value.ukm.addedukm,
        'public': value.ukm.ephemeralPublicKey,
      },
      sessionEncryptedKey: value.sessionEncryptedKey,
    }
  },
})

const GostEncryptedKey = (function (typeSet) {
  /**
     * Gost Encrypted key encoder for CMS
     *
     * @class GostASN1.GostEncryptedKey
     * @extends GostASN1.Sequence
     * @param {AlgorithmIdentifier} algorithm
     */
  return function (algorithm) {
    const type = typeSet[algorithm.id]
    return type ? ENCAPSULATES(type) : ANY
  }
})({
  // Key transport algorithms
  'id-sc-gostR3410-2001': SCGostKeyTransport,
  'id-sc-gostR3410-94': SCGostKeyTransport,
  'id-GostR3410-2001': GostR3410KeyTransport,
  'id-GostR3410-94': GostR3410KeyTransport,
  'id-tc26-gost3410-12-256': GostR3410KeyTransport,
  'id-tc26-gost3410-12-512': GostR3410KeyTransport,
  // Key agreement algorithms
  'id-GostR3410-94-CryptoPro-ESDH': Gost2814789EncryptedKey,
  'id-GostR3410-2001-CryptoPro-ESDH': Gost2814789EncryptedKey,
  'id-tc26-agreement-gost-3410-12-256': Gost2814789EncryptedKey,
  'id-tc26-agreement-gost-3410-12-512': Gost2814789EncryptedKey,
  'id-sc-r3410-ESDH-r3411kdf': Gost2814789EncryptedKey,
  // Key encryption key algorithms
  'id-Gost28147-89-None-KeyWrap': Gost2814789EncryptedKey,
  'id-Gost28147-89-CryptoPro-KeyWrap': Gost2814789EncryptedKey,
  'id-sc-cmsGostWrap': Gost2814789EncryptedKey,
  'id-sc-cmsGost28147Wrap': Gost2814789EncryptedKey,
})

// </editor-fold>

/*
 * CryptoPro Gost Private Key Store
 */ // <editor-fold defaultstate="collapsed">

const GostKeyContainerContentAttributes = BIT_STRING({
  kccaSoftPassword: 0,
  kccaReservePrimary: 1,
  kccaPrimaryKeyAbsent: 2,
  kccaFKCShared: 3,
})

const GostPrivateKeyAttributes = BIT_STRING({
  pkaExportable: 0,
  pkaUserProtect: 1,
  pkaExchange: 2,
  pkaEphemeral: 3,
  pkaNonCachable: 4,
  pkaDhAllowed: 5,
})

const GostPrivateKeyParameters = SEQUENCE({
  attributes: OPTIONAL(GostPrivateKeyAttributes),
  privateKeyAlgorithm: OPTIONAL(CTX(0, IMPLICIT(KeyAlgorithmIdentifier))),
})

const CertificateLink = SEQUENCE({
  path: IA5String,
  hmac: Gost2814789MAC,
})

const PasswordPolicy = AlgorithmIdentifier

const GostKeyContainerContent = SEQUENCE({
  containerAlgoritmIdentifier: OPTIONAL(CTX(0, IMPLICIT(AlgorithmIdentifier))),
  containerName: OPTIONAL(IA5String),
  attributes: GostKeyContainerContentAttributes,
  primaryPrivateKeyParameters: GostPrivateKeyParameters,
  hmacPassword: OPTIONAL(CTX(2, IMPLICIT(Gost2814789MAC))),
  secondaryEncryptedPrivateKey: OPTIONAL(CTX(3, IMPLICIT(Gost2814789EncryptedKey))),
  secondaryPrivateKeyParameters: OPTIONAL(CTX(4, IMPLICIT(GostPrivateKeyParameters))),
  primaryCertificate: OPTIONAL(CTX(5, IMPLICIT(OCTET_STRING(ENCAPSULATES(Certificate))))),
  secondaryCertificate: OPTIONAL(CTX(6, IMPLICIT(OCTET_STRING(ENCAPSULATES(Certificate))))),
  encryptionContainerName: OPTIONAL(CTX(7, IMPLICIT(IA5String))),
  primaryCertificateLink: OPTIONAL(CTX(8, IMPLICIT(CertificateLink))),
  secondaryCertificateLink: OPTIONAL(CTX(9, IMPLICIT(CertificateLink))),
  primaryFP: OPTIONAL(CTX(10, IMPLICIT(OCTET_STRING))),
  secondaryFP: OPTIONAL(CTX(11, IMPLICIT(OCTET_STRING))),
  passwordPolicy: OPTIONAL(PasswordPolicy),
  containerSecurityLevel: OPTIONAL(INTEGER),
  extensions: OPTIONAL(CTX(12, IMPLICIT(Extensions({
    keyValidity: SEQUENCE({
      notBefore: OPTIONAL(CTX(0, IMPLICIT(GeneralizedTime))),
      notAfter: OPTIONAL(CTX(1, IMPLICIT(GeneralizedTime))),
    }),
  })))),
  secondaryEncryptionContainerName: OPTIONAL(CTX(13, IMPLICIT(IA5String))),
})

/**
 * CryptoPro key container header
 *
 * @class GostASN1.GostKeyContainer
 * @extends GostASN1.Sequence
 */
const GostKeyContainer = SEQUENCE({
  keyContainerContent: GostKeyContainerContent,
  hmacKeyContainerContent: Gost2814789MAC,
})

/**
 * CryptoPro key container name
 *
 * @class GostASN1.GostKeyContainerName
 * @extends GostASN1.Sequence
 */
const GostKeyContainerName = SEQUENCE({
  containerName: IA5String,
  extElem1: OPTIONAL(ANY),
})

/**
 * PrivateKey encrypted content for CryptoPro key containers
 *
 * @class GostASN1.GostPrivateKeys
 * @extends GostASN1.Sequence
 */
const GostPrivateKeys = SEQUENCE({
  primaryKey: Gost2814789Key,
  secondaryKey: OPTIONAL(Gost2814789Key),
  hmacKey: OPTIONAL(Gost2814789MAC),
})

/**
 * PrivateKey masks for CryptoPro key containers
 *
 * @class GostASN1.GostPrivateMasks
 * @extends GostASN1.Sequence
 */
const GostPrivateMasks = SEQUENCE({
  mask: Gost2814789Key,
  randomStatus: OCTET_STRING,
  hmacRandom: Gost2814789MAC,
})

// </editor-fold>

/*
 * ViPNet Gost Private Key Store
 */ // <editor-fold defaultstate="collapsed">

const ViPNetKeyInfo = SEQUENCE({
  keyClass: INTEGER,
  keyType: INTEGER,
  algorithm: OPTIONAL(CTX(0, EXPLICIT(KeyAlgorithmIdentifier))),
  serialNumber: OPTIONAL(CTX(1, EXPLICIT(OCTET_STRING))),
  addSerialNumber: OPTIONAL(CTX(2, EXPLICIT(OCTET_STRING))),
  certSerialNumber: OPTIONAL(CTX(3, EXPLICIT(OCTET_STRING))),
  subjectUID: OPTIONAL(CTX(4, EXPLICIT(OCTET_STRING))),
  recipientUID: OPTIONAL(CTX(5, EXPLICIT(OCTET_STRING))),
  validity: OPTIONAL(CTX(6, EXPLICIT(CHOICE({
    validity: Validity,
    keyValidity: SEQUENCE({
      notBefore: OPTIONAL(CTX(0, IMPLICIT(GeneralizedTime))),
      notAfter: OPTIONAL(CTX(1, IMPLICIT(GeneralizedTime))),
    }),
  }, function () {
    return 'keyValidity'
  })))),
  keyUID: OPTIONAL(CTX(7, EXPLICIT(BIT_STRING))),
  flags: OPTIONAL(CTX(10, EXPLICIT(INTEGER))),
})

/**
 * ViPNet key container info
 *
 * @class GostASN1.ViPNetInfo
 * @extends GostASN1.Sequence
 */
const ViPNetInfo = SEQUENCE({
  version: INTEGER,
  keyInfo: ViPNetKeyInfo,
  defenceKeyInfo: ViPNetKeyInfo,
  certificate: OPTIONAL(CTX(0, EXPLICIT(Certificate))),
  publicKey: OPTIONAL(CTX(1, EXPLICIT(OCTET_STRING))),
})

// </editor-fold>

/*
 * Cryptographic Message Syntax
 *
 * http://tools.ietf.org/html/rfc5652
 *
 */ // <editor-fold defaultstate="collapsed">

// CMS signed data
const CMSVersion = INTEGER

var ContentType = OBJECT_IDENTIFIER

const SigningTime = Time

var SubjectKeyIdentifier = OCTET_STRING

const Digest = OCTET_STRING

const MessageAuthenticationCode = OCTET_STRING

const BodyPartID = INTEGER

const BodyPartPath = SEQUENCE_OF(BodyPartID)

const CMCUnsignedData = SEQUENCE({
  bodyPartPath: BodyPartPath,
  identifier: OBJECT_IDENTIFIER,
  content: ANY,
}) // DEFINED BY identifier
/**
 * SignedAttributes is a collection of attributes that are signed.  The
 * field is optional, but it MUST be present if the content type of
 * the EncapsulatedContentInfo value being signed is not id-data.
 * SignedAttributes MUST be DER encoded, even if the rest of the
 * structure is BER encoded.  Useful attribute types, such as signing
 * time, are defined in Section 11.  If the field is present, it MUST
 * contain, at a minimum, the following two attributes: <br>
 *
 * A content-type attribute having as its value the content type
 * of the EncapsulatedContentInfo value being signed.  Section
 * 11.1 defines the content-type attribute.  However, the
 * content-type attribute MUST NOT be used as part of a
 * countersignature unsigned attribute as defined in Section 11.4.<br>
 *
 * A message-digest attribute, having as its value the message
 * digest of the content.  Section 11.2 defines the message-digest
 * attribute.
 *
 * @class GostASN1.SignedAttributes
 * @extends GostASN1.Attributes
 */
const SignedAttributes = Attributes({
  contentType: SET_OF_SINGLE(ContentType),
  signingTime: SET_OF_SINGLE(SigningTime),
  messageDigest: SET_OF_SINGLE(OCTET_STRING),
})

const UnsignedAttributes = Attributes(function (type) {
  /**
     * UnsignedAttributes is a collection of attributes that are not signed.
     * The field is optional.  Useful attribute types, such as
     * countersignatures.
     *
     * @class GostASN1.UnsignedAttributes
     * @extends GostASN1.Attributes
     */
  //    var UnsignedAttributes = Attributes({
  //        countersignature: SET_OF(Countersignature), // -- check forward
  //        unsignedData: SET_OF(CMCUnsignedData)
  //    });
  return ({
    countersignature: SET_OF(Countersignature), // recursion
    unsignedData: SET_OF(CMCUnsignedData),
  })[type]
})

const AuthAttributes = SignedAttributes,
  UnauthAttributes = Attributes,
  UnprotectedAttributes = Attributes

const IssuerAndSerialNumber = SEQUENCE({
  issuer: Name,
  serialNumber: CertificateSerialNumber,
})

const SignerIdentifier = CHOICE({
  issuerAndSerialNumber: IssuerAndSerialNumber,
  subjectKeyIdentifier: CTX(0, IMPLICIT(SubjectKeyIdentifier)),
}, function (value) {
  return isBinary(value) ? 'subjectKeyIdentifier' : 'issuerAndSerialNumber'
})

const SignerInfo = SEQUENCE({
  version: CMSVersion,
  sid: SignerIdentifier,
  digestAlgorithm: DigestAlgorithmIdentifier,
  signedAttrs: OPTIONAL(CTX(0, IMPLICIT(SignedAttributes))),
  signatureAlgorithm: SignatureAlgorithmIdentifier,
  signatureValue: OCTET_STRING,
  unsignedAttrs: OPTIONAL(CTX(1, IMPLICIT(UnsignedAttributes))),
})

var Countersignature = SignerInfo,
  SignerInfos = SET_OF(SignerInfo),
  DigestAlgorithmIdentifiers = SET_OF(DigestAlgorithmIdentifier),
  AttributeCertificateV2 = AttributeCertificate

const ExtendedCertificateInfo = COMBINE(SEQUENCE({
  version: CMSVersion,
  certificate: Certificate,
  attributes: UnauthAttributes,
}))

const ExtendedCertificate = SEQUENCE({
  extendedCertificateInfo: ExtendedCertificateInfo,
  signatureAlgorithm: SignatureAlgorithmIdentifier,
  signatureValue: BIT_STRING,
})

const OtherCertificateFormat = SEQUENCE({
  otherCertFormat: OBJECT_IDENTIFIER,
  otherCert: ANY,
})

const AttributeCertificateInfoV1 = COMBINE(SEQUENCE({
  version: INTEGER,
  subject: CHOICE({
    baseCertificateID: CTX(0, IMPLICIT(IssuerSerial)), // associated with a Public Key Certificate
    subjectName: CTX(1, IMPLICIT(GeneralNames)),
  }, function (value) {
    return value.issuer ? 'baseCertificateID' : 'subjectName'
  }), //associated with a name
  issuer: GeneralNames,
  signature: SignatureAlgorithmIdentifier,
  serialNumber: CertificateSerialNumber,
  attCertValidityPeriod: AttCertValidityPeriod,
  attributes: AttributeSequence,
  issuerUniqueID: OPTIONAL(UniqueIdentifier),
  extensions: OPTIONAL(CertExtensions),
}))

const AttributeCertificateV1 = SEQUENCE({
  acInfo: AttributeCertificateInfoV1,
  signatureAlgorithm: SignatureAlgorithmIdentifier,
  signatureValue: BIT_STRING,
})

const EncapsulatedContentInfo = SEQUENCE({
  eContentType: ContentType,
  eContent: OPTIONAL(CTX(0, EXPLICIT(OCTET_STRING))),
})

const CertificateChoices = CHOICE({
  certificate: Certificate,
  extendedCertificate: CTX(0, IMPLICIT(ExtendedCertificate)), // Obsolete
  v1AttrCert: CTX(1, IMPLICIT(AttributeCertificateV1)), // Obsolete
  v2AttrCert: CTX(2, IMPLICIT(AttributeCertificateV2)),
  other: CTX(3, IMPLICIT(OtherCertificateFormat)),
}, function (value) {
  return value.holder ? 'AttributeCertificateV2' : value.certificate ?
    'ExtendedCertificate' : value.otherCertFormat ? 'other' :
      'certificate'
})

const OtherRevocationInfoFormat = SEQUENCE({
  otherRevInfoFormat: OBJECT_IDENTIFIER,
  otherRevInfo: ANY,
})

const RevocationInfoChoice = CHOICE({
  crl: CertificateList,
  other: CTX(1, IMPLICIT(OtherRevocationInfoFormat)),
}, function (value) {
  return value.otherRevInfoFormat ? 'other' : 'crl'
})

const CertificateSet = SET_OF(CertificateChoices),
  RevocationInfoChoices = SET_OF(RevocationInfoChoice)

/**
 * The signed-data content type consists of a content of any type and zero or more
 * signature values.  Any number of signers in parallel can sign any type of content.<br><br>
 *
 * The signed-data content type shall have ASN.1 type SignedData:<br><br>
 *<pre>
 *
 *      SignedData ::= SEQUENCE {
 *        version CMSVersion,
 *        digestAlgorithms DigestAlgorithmIdentifiers,
 *        encapContentInfo EncapsulatedContentInfo,
 *        certificates [0] IMPLICIT CertificateSet OPTIONAL,
 *        crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
 *        signerInfos SignerInfos }
 *
 *      DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
 *
 *      SignerInfos ::= SET OF SignerInfo
 *
 *       EncapsulatedContentInfo ::= SEQUENCE {
 *        eContentType ContentType,
 *        eContent [0] EXPLICIT OCTET STRING OPTIONAL }
 *
 *</pre>
 * Per-signer information is represented in the type SignerInfo:<br><br>
 *<pre>
 *
 *      SignerInfo ::= SEQUENCE {
 *        version CMSVersion,
 *        sid SignerIdentifier,
 *        digestAlgorithm DigestAlgorithmIdentifier,
 *        signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
 *        signatureAlgorithm SignatureAlgorithmIdentifier,
 *        signature SignatureValue,
 *        unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
 *
 *      SignerIdentifier ::= CHOICE {
 *        issuerAndSerialNumber IssuerAndSerialNumber,
 *        subjectKeyIdentifier [0] SubjectKeyIdentifier }
 *
 *      SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
 *
 *      UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
 *
 *     SignatureValue ::= OCTET STRING
 *
 *</pre>
 * See also {@link GostASN1.SignedAttributes} and {@link GostASN1.UnsignedAttributes}
 * @class GostASN1.SignedData
 * @extends GostASN1.Sequence
 * @property {number} version The syntax version number
 * @property {AlgorithmIdentifier[]} digestAlgorithms Collection of message digest algorithm identifiers
 * @property {GostASN1.Sequence} encapContentInfo The content is represented in the type EncapsulatedContentInfo
 * @property {GostASN1.Certificate[]} certificates Certificates
 * @property {GostASN1.CertificateList[]} crls Certificates
 * @property {GostASN1.Sequence[]} signerInfos The Signer information
 */
const SignedData = SEQUENCE({
  version: CMSVersion,
  digestAlgorithms: DigestAlgorithmIdentifiers,
  encapContentInfo: EncapsulatedContentInfo,
  certificates: OPTIONAL(CTX(0, IMPLICIT(CertificateSet))),
  crls: OPTIONAL(CTX(1, IMPLICIT(RevocationInfoChoices))),
  signerInfos: SignerInfos,
})

const RecipientIdentifier = CHOICE({
  issuerAndSerialNumber: IssuerAndSerialNumber,
  subjectKeyIdentifier: CTX(0, IMPLICIT(SubjectKeyIdentifier)),
}, function (value) {
  return isBinary(value) ? 'subjectKeyIdentifier' : 'issuerAndSerialNumber'
})

const KeyTransRecipientInfo = SEQUENCE({
  version: CMSVersion, // always set to 0 or 2
  rid: RecipientIdentifier,
  keyEncryptionAlgorithm: KeyEncryptionAlgorithmIdentifier,
  encryptedKey: EncryptedKey,
})

const OtherKeyAttribute = SEQUENCE({
  keyAttrId: OBJECT_IDENTIFIER,
  keyAttr: OPTIONAL(ANY),
})

const RecipientKeyIdentifier = SEQUENCE({
  subjectKeyIdentifier: SubjectKeyIdentifier,
  date: OPTIONAL(GeneralizedTime),
  other: OPTIONAL(OtherKeyAttribute),
})

const KeyAgreeRecipientIdentifier = CHOICE({
  issuerAndSerialNumber: IssuerAndSerialNumber,
  rKeyId: CTX(0, IMPLICIT(RecipientKeyIdentifier)),
}, function (value) {
  return isBinary(value) ? 'rKeyId' : 'issuerAndSerialNumber'
})

const RecipientEncryptedKey = SEQUENCE({
  rid: KeyAgreeRecipientIdentifier,
  encryptedKey: EncryptedKey,
})

const RecipientEncryptedKeys = SEQUENCE_OF(RecipientEncryptedKey)

const OriginatorPublicKey = SEQUENCE({
  algorithm: KeyAlgorithmIdentifier,
  publicKey: BIT_STRING,
})

const MQVuserKeyingMaterial = SEQUENCE({ // ECC rfc5753 KeyAgreeRecipientInfo in ukm
  ephemeralPublicKey: OriginatorPublicKey,
  addedukm: OPTIONAL(CTX(0, EXPLICIT(UserKeyingMaterial))),
})

const OriginatorIdentifierOrKey = CHOICE({
  issuerAndSerialNumber: IssuerAndSerialNumber,
  subjectKeyIdentifier: CTX(0, IMPLICIT(SubjectKeyIdentifier)),
  originatorKey: CTX(1, IMPLICIT(OriginatorPublicKey)),
}, function (value) {
  return isBinary(value) ? 'subjectKeyIdentifier' : value.algorithm ?
    'originatorKey' : 'issuerAndSerialNumber'
})

const KeyAgreeRecipientInfo = SEQUENCE({
  version: CMSVersion, // always set to 3
  originator: CTX(0, EXPLICIT(OriginatorIdentifierOrKey)),
  ukm: OPTIONAL(CTX(1, EXPLICIT(UserKeyingMaterial))),
  keyEncryptionAlgorithm: KeyEncryptionAlgorithmIdentifier,
  recipientEncryptedKeys: RecipientEncryptedKeys,
})

const KEKIdentifier = SEQUENCE({
  keyIdentifier: OCTET_STRING,
  date: OPTIONAL(GeneralizedTime),
  other: OPTIONAL(OtherKeyAttribute),
})

const KEKRecipientInfo = SEQUENCE({
  version: CMSVersion, // always set to 4
  kekid: KEKIdentifier,
  keyEncryptionAlgorithm: KeyEncryptionAlgorithmIdentifier,
  encryptedKey: EncryptedKey,
})

const PasswordRecipientInfo = SEQUENCE({
  version: CMSVersion, // always set to 0
  friendlyName: OPTIONAL(CTX(0, IMPLICIT(KeyDerivationAlgorithmIdentifier))),
  keyEncryptionAlgorithm: KeyEncryptionAlgorithmIdentifier,
  encryptedKey: EncryptedKey,
})

const OtherRecipientInfo = SEQUENCE({
  oriType: OBJECT_IDENTIFIER,
  oriValue: ANY,
})

const RecipientInfo = CHOICE({
  ktri: KeyTransRecipientInfo,
  kari: CTX(1, IMPLICIT(KeyAgreeRecipientInfo)),
  kekri: CTX(2, IMPLICIT(KEKRecipientInfo)),
  pwri: CTX(3, IMPLICIT(PasswordRecipientInfo)),
  ori: CTX(4, IMPLICIT(OtherRecipientInfo)),
}, function (value) {
  return value.rid ? 'ktri' : value.originator ? 'kari' :
    value.kekid ? 'kekri' : value.oriType ? 'ori' : 'pwri'
})

const OriginatorInfo = SEQUENCE({
  certs: OPTIONAL(CTX(0, IMPLICIT(CertificateSet))),
  crls: OPTIONAL(CTX(1, IMPLICIT(RevocationInfoChoices))),
})

const RecipientInfos = SET_OF(RecipientInfo)

// EncryptedContentInfo
const EncryptedContentInfo = SEQUENCE({
  contentType: ContentType,
  contentEncryptionAlgorithm: ContentEncryptionAlgorithmIdentifier,
  encryptedContent: OPTIONAL(CTX(0, IMPLICIT(EncryptedContent))),
})

/**
 * The enveloped-data content type consists of an encrypted content of
 * any type and encrypted content-encryption keys for one or more
 * recipients.  The combination of the encrypted content and one
 * encrypted content-encryption key for a recipient is a "digital
 * envelope" for that recipient.  Any type of content can be enveloped
 * for an arbitrary number of recipients using any of the supported key
 * management techniques for each recipient.<br><br>
 *
 * The typical application of the enveloped-data content type will
 * represent one or more recipients' digital envelopes on content of the
 * data or signed-data content types.<br><br>
 * <pre>
 *
 *      EnvelopedData ::= SEQUENCE {
 *        version CMSVersion,
 *        originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *        recipientInfos RecipientInfos,
 *        encryptedContentInfo EncryptedContentInfo,
 *        unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
 *
 *      OriginatorInfo ::= SEQUENCE {
 *        certs [0] IMPLICIT CertificateSet OPTIONAL,
 *        crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }
 *
 *      RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo
 *
 *      EncryptedContentInfo ::= SEQUENCE {
 *        contentType ContentType,
 *        contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *        encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
 *
 *      EncryptedContent ::= OCTET STRING
 *
 *      UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute
 *
 * </pre>
 * @class GostASN1.EnvelopedData
 * @extends GostASN1.Sequence
 * @property {number} version The syntax version number
 * @property {GostASN1.Sequence} originatorInfo Optionally provides information about the originator.
 * @property {GostASN1.Sequence[]} recipientInfos Collection of per-recipient information.
 * @property {GostASN1.Sequence} encryptedContentInfo The content is represented in the type EncryptedContentInfo
 * @property {Attributes} unprotectedAttrs The unprotected attributes
 */
const EnvelopedData = SEQUENCE({
  version: CMSVersion,
  originatorInfo: OPTIONAL(CTX(0, IMPLICIT(OriginatorInfo))),
  recipientInfos: RecipientInfos,
  encryptedContentInfo: EncryptedContentInfo,
  unprotectedAttrs: OPTIONAL(CTX(1, IMPLICIT(UnprotectedAttributes))),
})

/**
 * The digested-data content type consists of content of any type and a
 * message digest of the content.<br><br>
 * Typically, the digested-data content type is used to provide content
 * integrity, and the result generally becomes an input to the
 * enveloped-data content type.<br><br>
 * <pre>
 *
 *      DigestedData ::= SEQUENCE {
 *        version CMSVersion,
 *        digestAlgorithm DigestAlgorithmIdentifier,
 *        encapContentInfo EncapsulatedContentInfo,
 *        digest Digest }
 *
 *      Digest ::= OCTET STRING
 *
 *</pre>
 * @class GostASN1.DigestedData
 * @extends GostASN1.Sequence
 * @property {number} version The syntax version number
 * @property {AlgorithmIdentifier} digestAlgorithm Message digest algorithm identifier
 * @property {GostASN1.Sequence} encapContentInfo The content is represented in the type EncapsulatedContentInfo
 * @property {CryptoOperationData} digest The degist
 */
const DigestedData = SEQUENCE({
  version: CMSVersion,
  digestAlgorithm: DigestAlgorithmIdentifier,
  encapContentInfo: EncapsulatedContentInfo,
  digest: Digest,
})

/**
 * The encrypted-data content type consists of encrypted content of any
 * type.  Unlike the enveloped-data content type, the encrypted-data
 * content type has neither recipients nor encrypted content-encryption
 * keys.  Keys MUST be managed by other means.<br><br>
 *
 * The typical application of the encrypted-data content type will be to
 * encrypt the content of the data content type for local storage,
 * perhaps where the encryption key is derived from a password.<br><br>
 * <pre>
 *
 *      EncryptedData ::= SEQUENCE {
 *        version CMSVersion,
 *        encryptedContentInfo EncryptedContentInfo,
 *        unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
 *
 *      EncryptedContentInfo ::= SEQUENCE {
 *        contentType ContentType,
 *        contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
 *        encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
 *
 *      EncryptedContent ::= OCTET STRING
 *
 * </pre>
 * @class GostASN1.EncryptedData
 * @extends GostASN1.Sequence
 * @property {number} version The syntax version number
 * @property {GostASN1.Sequence} encryptedContentInfo The content is represented in the type EncryptedContentInfo
 * @property {Attributes} unprotectedAttrs The unprotected attributes
 */
const EncryptedData = SEQUENCE({
  version: CMSVersion,
  encryptedContentInfo: EncryptedContentInfo,
  unprotectedAttrs: OPTIONAL(CTX(1, IMPLICIT(UnprotectedAttributes))),
})

/**
 * The authenticated-data content type consists of content of any type,
 * a message authentication code (MAC), and encrypted authentication
 * keys for one or more recipients.  The combination of the MAC and one
 * encrypted authentication key for a recipient is necessary for that
 * recipient to verify the integrity of the content.  Any type of
 * content can be integrity protected for an arbitrary number of
 * recipients.<br><br>
 * <pre>
 *
 *      AuthenticatedData ::= SEQUENCE {
 *        version CMSVersion,
 *        originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *        recipientInfos RecipientInfos,
 *        macAlgorithm MessageAuthenticationCodeAlgorithm,
 *        digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
 *        encapContentInfo EncapsulatedContentInfo,
 *        authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
 *        mac MessageAuthenticationCode,
 *        unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
 *
 *      AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
 *
 *      UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
 *
 *      MessageAuthenticationCode ::= OCTET STRING
 *
 * </pre>
 * @class GostASN1.AuthenticatedData
 * @extends GostASN1.Sequence
 * @property {number} version The syntax version number
 * @property {GostASN1.Sequence} originatorInfo Optionally provides information about the originator.
 * @property {GostASN1.Sequence[]} recipientInfos Collection of per-recipient information.
 * @property {AlgorithmIdentifier} macAlgorithm Identifies the Message Authentication Code algorithm
 * @property {AlgorithmIdentifier} digestAlgorithm Identifies the Digest algorithm
 * @property {GostASN1.Sequence} encapContentInfo The content is represented in the type EncapsulatedContentInfo
 * @property {Attributes} authAttrs The autheniticated attributes
 * @property {CryptoOpertionData} mac The Message Authentication Code
 * @property {Attributes} unauthAttrs The unautheniticated attributes
 */
const AuthenticatedData = SEQUENCE({
  version: CMSVersion,
  originatorInfo: OPTIONAL(CTX(0, IMPLICIT(OriginatorInfo))),
  recipientInfos: RecipientInfos,
  macAlgorithm: MessageAuthenticationCodeAlgorithm,
  digestAlgorithm: OPTIONAL(CTX(1, DigestAlgorithmIdentifier)),
  encapContentInfo: EncapsulatedContentInfo,
  authAttrs: OPTIONAL(CTX(2, IMPLICIT(AuthAttributes))),
  mac: MessageAuthenticationCode,
  unauthAttrs: OPTIONAL(CTX(3, IMPLICIT(UnauthAttributes))),
})

// AuthEnvelopedData RFC 5911
const AuthEnvelopedData = SEQUENCE({
  version: CMSVersion,
  originatorInfo: OPTIONAL(CTX(0, IMPLICIT(OriginatorInfo))),
  recipientInfos: RecipientInfos,
  authEncryptedContentInfo: EncryptedContentInfo,
  authAttrs: OPTIONAL(CTX(1, IMPLICIT(AuthAttributes))),
  mac: MessageAuthenticationCode,
  unauthAttrs: OPTIONAL(CTX(2, IMPLICIT(UnauthAttributes))),
})

// EncryptedKeyPackage rfc6032
const EncryptedKeyPackage = CHOICE({
  encrypted: EncryptedData,
  enveloped: CTX(0, IMPLICIT(EnvelopedData)),
  authEnveloped: CTX(1, IMPLICIT(AuthEnvelopedData)),
}, function (value) {
  return value.encryptedContentInfo ? (value.recipientInfos ?
    'enveloped' : 'encrypted') : 'authEnveloped'
})

/**
 * Cryptographic Message Syntax<br>
 * The CMS associates a content type identifier with a content. The syntax
 * MUST have ASN.1 type ContentInfo:
 * <pre>
 *
 *  ContentInfo ::= SEQUENCE {
 *    contentType ContentType,
 *    content [0] EXPLICIT ANY DEFINED BY contentType }
 *
 *  ContentType ::= OBJECT IDENTIFIER
 *
 * </pre>
 * The fields of ContentInfo have the following meanings:
 * <ul>
 * <li>contentType indicates the type of the associated content.  It is
 * an object identifier; it is a unique string of integers assigned
 * by an authority that defines the content type.</li>
 * <li>content is the associated content.  The type of content can be
 * determined uniquely by contentType.  Content types for data,
 * signed-data, enveloped-data, digested-data, encrypted-data, and
 * authenticated-data are defined in this document.  If additional
 * content types are defined in other documents, the ASN.1 type
 * defined SHOULD NOT be a CHOICE type.</li>
 * </ul>
 * RFC 5652 references {@link http://tools.ietf.org/html/rfc5652}
 *
 * @class GostASN1.ContentInfo
 * @extends GostASN1.Sequence
 * @property {string} contentType The content type identifier
 * @property {(GostASN1.Sequence|CryptoOperationData)} content The content
 */
var ContentType = OBJECT_IDENTIFIER

const ContentInfo = ATTRIBUTE({
  contentType: ContentType,
  content: function (type) {
    return CTX(0, EXPLICIT(type))
  },
}, 'contentType', 'content', undefined, 'CMS')({
  data: OCTET_STRING,
  signedData: COMBINE(SignedData),
  envelopedData: COMBINE(EnvelopedData),
  digestedData: COMBINE(DigestedData),
  encryptedData: COMBINE(EncryptedData),
  authData: COMBINE(AuthenticatedData),
  encryptedKeyPkg: COMBINE(EncryptedKeyPackage),
  aKeyPackage: COMBINE(AsymmetricKeyPackage),
})

const DigestInfo = SEQUENCE({
  digestAlgorithm: DigestAlgorithmIdentifier,
  digest: Digest,
})
// </editor-fold>

/*
 * PFX format syntax PKCS#12
 *
 * http://tools.ietf.org/html/rfc7292
 *
 */ // <editor-fold defaultstate="collapsed">

const PKCS12Attributes = Attributes({
  friendlyName: SET_OF_SINGLE(BMPString),
  keyProviderNameAttr: SET_OF_SINGLE(BMPString),
  localKeyId: SET_OF_SINGLE(OCTET_STRING),
  certKeyIdentifierPropId: SET_OF_SINGLE(OCTET_STRING),
})

const SafeBagType = OBJECT_IDENTIFIER

const CertType = OBJECT_IDENTIFIER

const CRLType = OBJECT_IDENTIFIER

const SecretType = OBJECT_IDENTIFIER

const KeyBag = PrivateKeyInfo

const PKCS8ShroudedKeyBag = EncryptedPrivateKeyInfo

const CertBag = ATTRIBUTE({
  certId: CertType,
  certValue: function (type) {
    return CTX(0, EXPLICIT(type))
  },
}, 'certId', 'certValue')({
  // DER-encoded X.509 certificate stored in OCTET STRING
  x509Certificate: OCTET_STRING(ENCAPSULATES(Certificate)),
  // Base64-encoded SDSI certificate stored in IA5String
  sdsiCertificate: IA5String,
}, OCTET_STRING)

const CRLBag = ATTRIBUTE({
  crlId: CRLType,
  crlValue: function (type) {
    return CTX(0, EXPLICIT(type))
  },
}, 'crlId', 'crlValue')({
  // DER-encoded X.509 certificate stored in OCTET STRING
  x509CRL: OCTET_STRING(ENCAPSULATES(CertificateList)),
}, OCTET_STRING)

const SecretBag = ATTRIBUTE({
  secretTypeId: SecretType,
  secretValue: function (type) {
    return CTX(0, EXPLICIT(type))
  },
}, 'secretTypeId', 'secretValue')({
  secret: OCTET_STRING,
}, OCTET_STRING)

const SafeBag = ATTRIBUTE({
  bagId: SafeBagType,
  bagValue: function (type) {
    return CTX(0, EXPLICIT(type))
  },
  bagAttributes: OPTIONAL(PKCS12Attributes),
}, 'bagId', 'bagValue')(function (type) {
  return ({
    keyBag: KeyBag,
    pkcs8ShroudedKeyBag: PKCS8ShroudedKeyBag,
    certBag: CertBag,
    crlBag: CRLBag,
    secretBag: SecretBag,
    safeContentsBag: SafeContents, // recursion
  })[type]
})

/**
 * The SafeContents Type<br><br>
 *
 * The sixth type of bag that can be held in a SafeBag is a
 * SafeContents. This recursive structure allows for arbitrary nesting
 * of multiple KeyBags, PKCS8ShroudedKeyBags, CertBags, CRLBags, and
 * SecretBags within the top-level SafeContents.
 * <pre>
 *  SafeContents ::= SEQUENCE OF SafeBag
 *   SafeBag ::= SEQUENCE {
 *       bagId BAG-TYPE.&id ({PKCS12BagSet})
 *       bagValue [0] EXPLICIT BAG-TYPE.&Type({PKCS12BagSet}{@bagId}),
 *       bagAttributes SET OF PKCS12Attribute OPTIONAL
 *   }
 *
 *   PKCS12Attribute ::= SEQUENCE {
 *       attrId ATTRIBUTE.&id ({PKCS12AttrSet}),
 *       attrValues SET OF ATTRIBUTE.&Type ({PKCS12AttrSet}{@attrId})
 *   } -- This type is compatible with the X.500 type ’Attribute’
 *
 *   PKCS12AttrSet ATTRIBUTE ::= {
 *       friendlyName | -- from PKCS #9 [23]
 *       localKeyId, -- from PKCS #9
 *       ... -- Other attributes are allowed
 *   }
 * </pre>
 * The SafeContents type is made up of SafeBags. Each SafeBag holds one
 * piece of information -- a key, a certificate, etc. -- which is
 * identified by an object identifier.<br><br>
 *
 * See {@link GostASN1.ContentInfo} and {@link GostASN1.PFX}<br><br>
 *
 * RFC 7292 references {@link http://tools.ietf.org/html/rfc7292}
 * @class GostASN1.SafeContents
 */
var SafeContents = SEQUENCE_OF(SafeBag)

/**
 * The AuthenticatedSafe<br><br>
 * Each compliant platform shall be able to import and export
 * AuthenticatedSafe PDUs wrapped in PFX PDUs.<br>
 * For integrity, the AuthenticatedSafe is either signed (if public-key
 * integrity mode is used) or MACed (if password integrity mode is used)
 * to produce a PFX PDU.
 * <pre>
 *      AuthenticatedSafe ::= SEQUENCE OF ContentInfo
 *
 *      -- Data if unencrypted
 *      -- EncryptedData if password-encrypted
 *      -- EnvelopedData if public key-encrypted
 * </pre>
 * As mentioned, the contentType field of authSafe shall be of type data
 * or signedData. The content field of the authSafe shall, either
 * directly (data case) or indirectly (signedData case), contain a BER-
 * encoded value of type AuthenticatedSafe.<br><br>
 *
 * See {@link GostASN1.ContentInfo} and {@link GostASN1.PFX}<br><br>
 *
 * RFC 7292 references {@link http://tools.ietf.org/html/rfc7292}
 *
 * @class GostASN1.AuthenticatedSafe
 */
const AuthenticatedSafe = SEQUENCE_OF(ContentInfo)

const MacData = SEQUENCE({
  mac: DigestInfo,
  macSalt: OCTET_STRING,
  // Note: The default is for historical reasons and its use is deprecated.
  iterations: DEFAULT(INTEGER, 1),
})

/**
 * PFX format syntax<br><br>
 *
 * This format corresponds to the data model presented above, with
 * wrappers for privacy and integrity. This section makes free
 * reference to PKCS #7 {@link GostASN1.ContentInfo}<br>
 * All modes of direct exchange use the same PDU format.  ASN.1 and BER-
 * encoding ensure platform independence.<br>
 * This standard has one ASN.1 export: PFX.  This is the outer integrity
 * wrapper.<br><br>
 * Instances of PFX contain:
 *  <ol>
 *  <li>A version indicator.  The version shall be v3 for this version of
 *      this document.</li>
 *  <li>A PKCS #7 ContentInfo, whose contentType is signedData in public-
 *      key integrity mode and data in password integrity mode.</li>
 *  <li>An optional instance of MacData, present only in password
 *      integrity.  This object, if present, contains a PKCS #7
 *      DigestInfo, which holds the MAC value, a macSalt, and an
 *      iterationCount.  As described in Appendix B, the MAC key is
 *      derived from the password, the macSalt, and the iterationCount;
 *      the MAC is computed from the authSafe value and the MAC key via HMAC.
 *      The password and the MAC key are not actually present anywhere in the PFX.
 *      The salt and (to a certain extent) the iteration count thwarts dictionary
 *      attacks against the integrity password. </li>
 *  </ol>
 *  <pre>
 *  PFX ::= SEQUENCE {
 *      version     INTEGER {v3(3)}(v3,...),
 *      authSafe    ContentInfo,
 *      macData     MacData OPTIONAL
 *  }
 *
 *  MacData ::= SEQUENCE {
 *      mac         DigestInfo,
 *      macSalt     OCTET STRING,
 *      iterations  INTEGER DEFAULT 1
 *      -- Note: The default is for historical reasons and its
 *      --       use is deprecated.
 *  }
 *  </pre>
 * See {@link GostASN1.ContentInfo}<br><br>
 *
 * RFC 7292 references {@link http://tools.ietf.org/html/rfc7292}
 * @class GostASN1.PFX
 * @extends GostASN1.Sequence
 * @property {number} version Encoded version number
 * @property {GostASN1.ContentInfo} authSafe ContentInfo with {@link GostASN1.AuthenticatedSafe} content
 */
const PFX = SEQUENCE({
  version: INTEGER,
  authSafe: ContentInfo,
  macData: OPTIONAL(MacData),
}, 'PFX')
// </editor-fold>

/*
 * Certificate Request Message Format
 *
 * http://tools.ietf.org/html/rfc4211
 *
 */ // <editor-fold defaultstate="collapsed">

const RegToken = UTF8String

const Authenticator = UTF8String

const CertId = SEQUENCE({
  issuer: GeneralName,
  serialNumber: INTEGER,
})
const OldCertId = CertId

const ProtocolEncrKey = SubjectPublicKeyInfo

const EncryptedValue = SEQUENCE({
  // the intended algorithm for which the value will be used
  intendedAlg: OPTIONAL(CTX(0, IMPLICIT(AlgorithmIdentifier))),
  // the symmetric algorithm used to encrypt the value
  symmAlg: OPTIONAL(CTX(1, IMPLICIT(AlgorithmIdentifier))),
  // the (encrypted) symmetric key used to encrypt the value
  encSymmKey: OPTIONAL(CTX(2, IMPLICIT(BIT_STRING))),
  // algorithm used to encrypt the symmetric key
  keyAlg: OPTIONAL(CTX(3, IMPLICIT(AlgorithmIdentifier))),
  valueHint: OPTIONAL(CTX(4, IMPLICIT(OCTET_STRING))),
  // a brief description or identifier of the encValue content
  // (may be meaningful only to the sending entity, and used only
  // if EncryptedValue might be re-examined by the sending entity
  // in the future)
  encValue: BIT_STRING,
})
const KeyGenParameters = OCTET_STRING

// The encrypted private key MUST be placed in the envelopedData
// encryptedContentInfo encryptedContent OCTET STRING.
var EncryptedKey = CHOICE({
  encryptedValue: EncryptedValue, // Deprecated
  envelopedData: CTX(0, IMPLICIT(EnvelopedData)),
}, function (value) {
  return value.encryptedContentInfo ? 'envelopedData' : 'encryptedValue'
})

const PKIArchiveOptions = CHOICE({
  // the actual value of the private key
  encryptedPrivKey: CTX(0, EncryptedKey),
  // parameters that allow the private key to be re-generated
  keyGenParameters: CTX(1, IMPLICIT(KeyGenParameters)),
  // set to TRUE if sender wishes receiver to archive the private
  // key of a key pair that the receiver generates in response to
  // this request; set to FALSE if no archival is desired.
  archiveRemGenPrivKey: CTX(2, IMPLICIT(BOOLEAN)),
})

const SinglePubInfo = SEQUENCE({
  pubMethod: INTEGER({
    dontCare: 0,
    x500: 1,
    web: 2,
    ldap: 3,
  }),
  pubLocation: OPTIONAL(GeneralName),
})

// pubInfos MUST NOT be present if action is "dontPublish"
// (if action is "pleasePublish" and pubInfos is omitted,
// "dontCare" is assumed)
const PKIPublicationInfo = SEQUENCE({
  action: INTEGER({
    dontPublish: 0,
    pleasePublish: 1,
  }),
  pubInfos: OPTIONAL(SEQUENCE_OF(SinglePubInfo)),
})

const SubsequentMessage = INTEGER({
  // requests that resulting certificate be encrypted for the
  // end entity (following which, POP will be proven in a
  // confirmation message)
  encrCert: 0,
  // requests that CA engage in challenge-response exchange with
  // end entity in order to prove private key possession
  challengeResp: 1,
})

const POPOPrivKey = CHOICE({
  // possession is proven in this message (which contains the private
  // key itself (encrypted for the CA))
  thisMessage: CTX(0, IMPLICIT(BIT_STRING)), // Deprecated
  subsequentMessage: CTX(1, IMPLICIT(SubsequentMessage)),
  // possession will be proven in a subsequent message
  dhMAC: CTX(2, IMPLICIT(BIT_STRING)), // Deprecated
  agreeMAC: CTX(3, IMPLICIT(PKMACValue)),
  encryptedKey: CTX(4, IMPLICIT(EnvelopedData)),
})

const PBMParameter = SEQUENCE({
  salt: OCTET_STRING,
  // AlgId for a One-Way Function (SHA-1 recommended)
  owf: AlgorithmIdentifier,
  // number of times the OWF is applied
  iterationCount: INTEGER,
  // the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11], or HMAC [HMAC, RFC2202])
  mac: AlgorithmIdentifier,
})

var PKMACValue = SEQUENCE({
  // algorithm value shall be PasswordBasedMac {1 2 840 113533 7 66 13}
  // parameter value is PBMParameter
  algId: AlgorithmIdentifier,
  value: BIT_STRING,
})

const POPOSigningKeyInput = SEQUENCE({
  authInfo: CHOICE({
    // used only if an authenticated identity has been
    // established for the sender (e.g., a DN from a
    // previously-issued and currently-valid certificate)
    sender: CTX(0, EXPLICIT(GeneralName)), // GeneralName choice - explicit
    // used if no authenticated GeneralName currently exists for
    // the sender; publicKeyMAC contains a password-based MAC
    // on the DER-encoded value of publicKey
    publicKeyMAC: PKMACValue,
  }),
  publicKey: SubjectPublicKeyInfo,
}) // from CertTemplate

const POPOSigningKey = SEQUENCE({
  poposkInput: OPTIONAL(CTX(0, POPOSigningKeyInput)),
  algorithmIdentifier: AlgorithmIdentifier,
  signature: BIT_STRING,
})

const ProofOfPossession = CHOICE({
  // used if the RA has already verified that the requester is in
  // possession of the private key
  raVerified: CTX(0, IMPLICIT(NULL)),
  signature: CTX(1, IMPLICIT(POPOSigningKey)),
  keyEncipherment: CTX(2, IMPLICIT(POPOPrivKey)),
  keyAgreement: CTX(3, IMPLICIT(POPOPrivKey)),
})

const Controls = SEQUENCE_OF(AttributeTypeAndValue({
  regToken: RegToken,
  authenticator: Authenticator,
  pkiPublicationInfo: PKIPublicationInfo,
  pkiArchiveOptions: PKIArchiveOptions,
  oldCertID: OldCertId,
  protocolEncrKey: ProtocolEncrKey,
}))

const OptionalValidity = SEQUENCE({
  notBefore: OPTIONAL(CTX(0, IMPLICIT(Time))),
  notAfter: OPTIONAL(CTX(1, IMPLICIT(Time))),
}) // at least one MUST be present

const CertTemplate = SEQUENCE({
  version: OPTIONAL(CTX(0, IMPLICIT(Version))),
  serialNumber: OPTIONAL(CTX(1, IMPLICIT(INTEGER))),
  signingAlg: OPTIONAL(CTX(2, IMPLICIT(AlgorithmIdentifier))),
  issuer: OPTIONAL(CTX(3, IMPLICIT(Name))),
  validity: OPTIONAL(CTX(4, IMPLICIT(OptionalValidity))),
  subject: OPTIONAL(CTX(5, IMPLICIT(Name))),
  publicKey: OPTIONAL(CTX(6, IMPLICIT(SubjectPublicKeyInfo))),
  issuerUID: OPTIONAL(CTX(7, IMPLICIT(UniqueIdentifier))),
  subjectUID: OPTIONAL(CTX(8, IMPLICIT(UniqueIdentifier))),
  extensions: OPTIONAL(CTX(9, IMPLICIT(Extensions))),
})

const CertRequest = SEQUENCE({
  certReqId: INTEGER, // ID for matching request and reply
  certTemplate: CertTemplate, // Selected fields of cert to be issued
  controls: OPTIONAL(Controls),
}) // Attributes affecting issuance

const UTF8Pairs = UTF8String

const CertReq = CertRequest

const EncKeyWithID = SEQUENCE({
  privateKey: PrivateKeyInfo,
  identifier: OPTIONAL(CHOICE({
    string: UTF8String,
    generalName: GeneralName,
  }, function (value) {
    return typeof value === 'string' || value instanceof String ?
      'string' : 'generalName'
  })),
})

const CertReqMsg = SEQUENCE({
  certReq: CertRequest,
  popo: OPTIONAL(ProofOfPossession),
  // content depends upon key type
  regInfo: OPTIONAL(SEQUENCE_OF(AttributeTypeAndValue({
    utf8Pairs: UTF8Pairs,
    certReq: CertReq,
    encKeyWithID: EncKeyWithID,
  }))),
})

const CertReqMessages = SEQUENCE_OF(CertReqMsg)

// </editor-fold>

/*
 * Certificate Management over CMS
 *
 * http://tools.ietf.org/html/rfc5272
 *
 */ // <editor-fold defaultstate="collapsed">

const PendInfo = SEQUENCE({
  pendToken: OCTET_STRING,
  pendTime: GeneralizedTime,
})

const CMCStatus = INTEGER({
  success: 0,
  failed: 2,
  pending: 3,
  noSupport: 4,
  confirmRequired: 5,
  popRequired: 6,
  partial: 7,
})

const CMCFailInfo = INTEGER({
  badAlg: 0,
  badMessageCheck: 1,
  badRequest: 2,
  badTime: 3,
  badCertId: 4,
  unsupportedExt: 5,
  mustArchiveKeys: 6,
  badIdentity: 7,
  popRequired: 8,
  popFailed: 9,
  noKeyReuse: 10,
  internalCAError: 11,
  tryLater: 12,
  authDataFail: 13,
})

const CMCStatusInfo = SEQUENCE({
  cMCStatus: CMCStatus,
  bodyList: SEQUENCE_OF(BodyPartID),
  statusString: OPTIONAL(UTF8String),
  otherInfo: OPTIONAL(CHOICE({
    failInfo: CMCFailInfo,
    pendInfo: PendInfo,
  })),
})

const AddExtensions = SEQUENCE({
  pkiDataReference: BodyPartID,
  certReferences: SEQUENCE_OF(BodyPartID),
  extensions: SEQUENCE_OF(Extension),
})

const LraPopWitness = SEQUENCE({
  pkiDataBodyid: BodyPartID,
  bodyIds: SEQUENCE_OF(BodyPartID),
})

const GetCert = SEQUENCE({
  issuerName: GeneralName,
  serialNumber: INTEGER,
})

const GetCRL = SEQUENCE({
  issuerName: Name,
  cRLName: OPTIONAL(GeneralName),
  time: OPTIONAL(GeneralizedTime),
  reasons: OPTIONAL(ReasonFlags),
})

const RevokeRequest = SEQUENCE({
  issuerName: Name,
  serialNumber: INTEGER,
  reason: CRLReason,
  invalidityDate: OPTIONAL(GeneralizedTime),
  passphrase: OPTIONAL(OCTET_STRING),
  comment: OPTIONAL(UTF8String),
})

const DecryptedPOP = SEQUENCE({
  bodyPartID: BodyPartID,
  thePOPAlgID: AlgorithmIdentifier,
  thePOP: OCTET_STRING,
})

const CMCCertId = IssuerAndSerialNumber

const BodyPartReference = CHOICE({
  bodyPartID: BodyPartID,
  bodyPartPath: BodyPartPath,
})

const CMCStatusInfoV2 = SEQUENCE({
  cMCStatus: CMCStatus,
  bodyList: SEQUENCE_OF(BodyPartReference),
  statusString: OPTIONAL(UTF8String),
  otherInfo: OPTIONAL(CHOICE({
    failInfo: CMCFailInfo,
    pendInfo: PendInfo,
    extendedFailInfo: SEQUENCE({
      failInfoOID: OBJECT_IDENTIFIER,
      failInfoValue: AttributeValue,
    }),
  })),
})

const PublishTrustAnchors = SEQUENCE({
  seqNumber: INTEGER,
  hashAlgorithm: AlgorithmIdentifier,
  anchorHashes: SEQUENCE_OF(OCTET_STRING),
})

const AuthPublish = BodyPartID

const BodyPartList = SEQUENCE_OF(BodyPartID)

const CMCPublicationInfo = SEQUENCE({
  hashAlg: AlgorithmIdentifier,
  certHashes: SEQUENCE_OF(OCTET_STRING),
  pubInfo: PKIPublicationInfo,
})

const ModCertTemplate = SEQUENCE({
  pkiDataReference: BodyPartPath,
  certReferences: BodyPartList,
  replace: DEFAULT(BOOLEAN, true),
  certTemplate: CertTemplate,
})

const ControlsProcessed = SEQUENCE({
  bodyList: SEQUENCE_OF(BodyPartReference),
})

const IdentifyProofV2 = SEQUENCE({
  proofAlgID: AlgorithmIdentifier,
  macAlgId: AlgorithmIdentifier,
  witness: OCTET_STRING,
})

const PopLinkWitnessV2 = SEQUENCE({
  keyGenAlgorithm: AlgorithmIdentifier,
  macAlgorithm: AlgorithmIdentifier,
  witness: OCTET_STRING,
})

const TaggedCertificationRequest = SEQUENCE({
  bodyPartID: BodyPartID,
  certificationRequest: CertificationRequest,
})

const TaggedContentInfo = SEQUENCE({
  bodyPartID: BodyPartID,
  contentInfo: ContentInfo,
})

const OtherMsg = SEQUENCE({
  bodyPartID: BodyPartID,
  otherMsgType: OBJECT_IDENTIFIER,
  otherMsgValue: ANY,
}) //DEFINED BY otherMsgType

const TaggedRequest = CHOICE({
  tcr: CTX(0, IMPLICIT(TaggedCertificationRequest)),
  crm: CTX(1, IMPLICIT(CertReqMsg)),
  orm: CTX(2, IMPLICIT(SEQUENCE({
    bodyPartID: BodyPartID,
    requestMessageType: OBJECT_IDENTIFIER,
    requestMessageValue: ANY,
  }))),
}) // DEFINED BY requestMessageType

const EncryptedPOP = SEQUENCE({
  request: TaggedRequest,
  cms: ContentInfo,
  thePOPAlgID: AlgorithmIdentifier,
  witnessAlgID: AlgorithmIdentifier,
  witness: OCTET_STRING,
})

const TaggedAttribute = ATTRIBUTE({
  bodyPartID: BodyPartID,
  attrType: OBJECT_IDENTIFIER,
  attrValues: function (type) {
    return SET_OF(type)
  },
}, 'attrType', 'attrValues', AttributeValue)({
  statusInfo: CMCStatusInfo,
  identification: UTF8String,
  identityProof: OCTET_STRING,
  dataReturn: OCTET_STRING,
  transactionId: INTEGER,
  senderNonce: OCTET_STRING,
  recipientNonce: OCTET_STRING,
  addExtensions: AddExtensions,
  encryptedPOP: EncryptedPOP,
  decryptedPOP: DecryptedPOP,
  lraPOPWitness: LraPopWitness,
  getCert: GetCert,
  getCRL: GetCRL,
  revokeRequest: RevokeRequest,
  regInfo: OCTET_STRING,
  responseInfo: OCTET_STRING,
  queryPending: OCTET_STRING,
  popLinkRandom: OCTET_STRING,
  popLinkWitness: OCTET_STRING,
  confirmCertAcceptance: CMCCertId,
  statusInfoV2: CMCStatusInfoV2,
  trustedAnchors: PublishTrustAnchors,
  authPublish: AuthPublish,
  batchRequests: BodyPartList,
  batchResponses: BodyPartList,
  publishCert: CMCPublicationInfo,
  modCertTemplate: ModCertTemplate,
  controlProcessed: ControlsProcessed,
  popLinkWitnessV2: PopLinkWitnessV2,
  identityProofV2: IdentifyProofV2,
})
/**
 * PKIData Content Type<br><br>
 *
 * The PKIData content type is used for the Full PKI Request.  A PKIData
 * content type is identified by:
 * <pre>
 *   id-cct-PKIData ::= {id-pkix id-cct(12) 2 }
 * </pre>
 * The ASN.1 structure corresponding to the PKIData content type is:
 * <pre>
 *   PKIData ::= SEQUENCE {
 *       controlSequence    SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
 *       reqSequence        SEQUENCE SIZE(0..MAX) OF TaggedRequest,
 *       cmsSequence        SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
 *       otherMsgSequence   SEQUENCE SIZE(0..MAX) OF OtherMsg
 *   }
 * </pre>
 * All certification requests encoded into a single PKIData SHOULD be
 * for the same identity.  RAs that batch process (see Section 6.17) are
 * expected to place the PKI Requests received into the cmsSequence of a
 * PKIData. <br><br>
 * See {@link GostASN1.ContentInfo} and {@link GostASN1.PKIResponse}<br><br>
 * RFC 5272 references {@link http://tools.ietf.org/html/rfc5272}
 *
 * @class GostASN1.PKIData
 * @extends GostASN1.Sequence
 * @property {GostASN1.Attributes[]} controlSequence
 * @property {GostASN1.Sequence[]} reqSequence
 * @property {GostASN1.ContentInfo[]} cmsSequence
 * @property {GostASN1.Sequence[]} otherMsgSequence
 */
const PKIData = SEQUENCE({
  controlSequence: SEQUENCE_OF(TaggedAttribute),
  reqSequence: SEQUENCE_OF(TaggedRequest),
  cmsSequence: SEQUENCE_OF(TaggedContentInfo),
  otherMsgSequence: SEQUENCE_OF(OtherMsg),
}, 'PKI REQUEST')

/**
 * PKIResponse Content Type<br><br>
 *
 * The PKIResponse content type is used for the Full PKI Response.  The
 * PKIResponse content type is identified by:
 * <pre>
 *   id-cct-PKIResponse ::= {id-pkix id-cct(12) 3  }
 * </pre>
 * The ASN.1 structure corresponding to the PKIResponse content type is:
 * <pre>
 *    PKIResponse ::= SEQUENCE {
 *        controlSequence   SEQUENCE SIZE(0..MAX) OF TaggedAttribute,
 *        cmsSequence       SEQUENCE SIZE(0..MAX) OF TaggedContentInfo,
 *        otherMsgSequence  SEQUENCE SIZE(0..MAX) OF OtherMsg
 *    }
 *
 *    ReponseBody ::= PKIResponse
 * </pre>
 *
 * Note: In [RFC2797], this ASN.1 type was named ResponseBody.  It has
 * been renamed to PKIResponse for clarity and the old name kept as a
 * synonym.<br><br>
 *
 * See {@link GostASN1.ContentInfo} and {@link GostASN1.PKIData}<br><br>
 *
 * RFC 5272 references {@link http://tools.ietf.org/html/rfc5272}
 *
 * @class GostASN1.PKIResponse
 * @extends GostASN1.Sequence
 * @property {GostASN1.Attributes[]} controlSequence
 * @property {GostASN1.ContentInfo[]} cmsSequence
 * @property {GostASN1.Sequence[]} otherMsgSequence
 */
const PKIResponse = SEQUENCE({
  controlSequence: SEQUENCE_OF(TaggedAttribute),
  cmsSequence: SEQUENCE_OF(TaggedContentInfo),
  otherMsgSequence: SEQUENCE_OF(OtherMsg),
}, 'PKI RESPONSE')

// </editor-fold>

/**
 * ASN.1 syntax definitions
 *
 * @class GostASN1
 */
function GostASN1() {
}

GostASN1.prototype = {
  /**
     * Gost PrivateKey info encoder
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.GostPrivateKeyInfo
     */
  GostPrivateKeyInfo: GostPrivateKeyInfo,
  /**
     * Gost subject PublicKey info encoder
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.GostSubjectPublicKeyInfo
     */
  GostSubjectPublicKeyInfo: GostSubjectPublicKeyInfo,
  /**
     * CryptoPro key container header
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.GostKeyContainer
     */
  GostKeyContainer: GostKeyContainer,
  /**
     * CryptoPro key container name
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.GostKeyContainerName
     */
  GostKeyContainerName: GostKeyContainerName,
  /**
     * CryptoPro encrypted PrivateKey for key containers
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.GostPrivateKeys
     */
  GostPrivateKeys: GostPrivateKeys,
  /**
     * CryptoPro PrivateKey masks for key containers
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.GostPrivateMasks
     */
  GostPrivateMasks: GostPrivateMasks,
  /**
     * ViPNet key container
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.ViPNetInfo
     */
  ViPNetInfo: ViPNetInfo,
  /**
     * Gost Signature encoders
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.GostSignature
     */
  GostSignature: GostSignature,
  /**
     * Gost Encrypted key encoder for CMS
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.GostEncryptedKey
     */
  GostEncryptedKey: GostEncryptedKey,
  /**
     * SignalCom wrapped PrivateKey
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.GostWrappedPrivateKey
     */
  GostWrappedPrivateKey: GostWrappedPrivateKey,
  /**
     * PKCS#8 PrivateKey info
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.PrivateKeyInfo
     */
  PrivateKeyInfo: PrivateKeyInfo,
  /**
     * PKCS#8 encrypted PrivateKey info
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.EncryptedPrivateKeyInfo
     */
  EncryptedPrivateKeyInfo: EncryptedPrivateKeyInfo,
  /**
     * X.509 subject PublicKey info
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.SubjectPublicKeyInfo
     */
  SubjectPublicKeyInfo: SubjectPublicKeyInfo,
  /**
     * X.509 To be signed Certificate
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.TBSCertificate
     */
  TBSCertificate: TBSCertificate,
  /**
     * X.509 Certificate
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.Certificate
     */
  Certificate: Certificate,
  /**
     * PKCS#10 Certification request definition
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.CertificationRequestInfo
     */
  CertificationRequestInfo: CertificationRequestInfo,
  /**
     * PKCS#10 Certification request
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.CertificationRequest
     */
  CertificationRequest: CertificationRequest,
  /**
     * X.509 To be signed CRL
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.TBSCertList
     */
  TBSCertList: TBSCertList,
  /**
     * X.509 CRL
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.CertificateList
     */
  CertificateList: CertificateList,
  /**
     * X.509 Attribute Certificate definition
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.AttributeCertificateInfo
     */
  AttributeCertificateInfo: AttributeCertificateInfo,
  /**
     * X.509 Attribute Certificate
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.AttributeCertificate
     */
  AttributeCertificate: AttributeCertificate,
  /**
     * CMS Signed Attributes
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.SignedAttributes
     */
  SignedAttributes: SignedAttributes,
  /**
     * CMS Unsigned Attributes
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.UnsignedAttributes
     */
  UnsignedAttributes: UnsignedAttributes,
  /**
     * CMS Content definition
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.ContentInfo
     */
  ContentInfo: ContentInfo,
  /**
     * PKCS#12 Safe Contents
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.SafeContents
     */
  SafeContents: SafeContents,
  /**
     * PKCS#12 Authenticated Safe
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.AuthenticatedSafe
     */
  AuthenticatedSafe: AuthenticatedSafe,
  /**
     * PKCS#12 Personal Information Exchange (PFX)
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.PFX
     */
  PFX: PFX,
  /**
     * PKI Request
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.PKIData
     */
  PKIData: PKIData,
  /**
     * PKI Response
     *
     * @memberOf GostASN1
     * @instance
     * @type GostASN1.PKIResponse
     */
  PKIResponse: PKIResponse,
}

/**
 * PKCS ASN.1 message syntax and converters
 *
 * @memberOf gostCrypto
 * @type GostASN1
 */
gostCrypto.asn1 = new GostASN1()

module.exports = GostASN1
