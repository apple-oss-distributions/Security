//   NOTE: this is a machine generated file--editing not recommended
//
// pkcs1oids.cpp - class member functions for ASN.1 module PKCS1-OIDS
//
//   This file was generated by snacc on Mon Apr 22 22:34:19 2002
//   UBC snacc written by Mike Sample
//   A couple of enhancements made by IBM European Networking Center


#include "asn-incl.h"
#include "sm_vdatypes.h"
#include "sm_x501ud.h"
#include "sm_x411ub.h"
#include "sm_x411mtsas.h"
#include "sm_x501if.h"
#include "sm_x520sa.h"
#include "sm_x509cmn.h"
#include "sm_x509af.h"
#include "sm_x509ce.h"
#include "pkcs1oids.h"
#include "pkcs9oids.h"
#include "sm_cms.h"
#include "sm_ess.h"
#include "pkcs7.h"
#include "pkcs8.h"
#include "appleoids.h"
#include "pkcs10.h"

//------------------------------------------------------------------------------
// value defs


//------------------------------------------------------------------------------
// class member definitions:

RSAPublicKey::RSAPublicKey()
{
}

RSAPublicKey::RSAPublicKey (const RSAPublicKey &)
{
  Asn1Error << "use of incompletely defined RSAPublicKey::RSAPublicKey (const RSAPublicKey &)" << endl;
  abort();
}

RSAPublicKey::~RSAPublicKey()
{
}

AsnType *RSAPublicKey::Clone() const
{
  return new RSAPublicKey;
}

AsnType *RSAPublicKey::Copy() const
{
  return new RSAPublicKey (*this);
}

#if SNACC_DEEP_COPY
RSAPublicKey &RSAPublicKey::operator = (const RSAPublicKey &that)
#else // SNACC_DEEP_COPY
RSAPublicKey &RSAPublicKey::operator = (const RSAPublicKey &)
#endif // SNACC_DEEP_COPY
{
#if SNACC_DEEP_COPY
  if (this != &that)
  {
    modulus = that.modulus;
    publicExponent = that.publicExponent;
  }

  return *this;
#else // SNACC_DEEP_COPY
  Asn1Error << "use of incompletely defined RSAPublicKey &RSAPublicKey::operator = (const RSAPublicKey &)" << endl;
  abort();
  // if your compiler complains here, check the -novolat option
#endif // SNACC_DEEP_COPY
}

AsnLen
RSAPublicKey::BEncContent (BUF_TYPE b)
{
  AsnLen totalLen = 0;
  AsnLen l;

    l = publicExponent.BEncContent (b);
    l += BEncDefLen (b, l);

    l += BEncTag1 (b, UNIV, PRIM, INTEGER_TAG_CODE);
    totalLen += l;

    l = modulus.BEncContent (b);
    l += BEncDefLen (b, l);

    l += BEncTag1 (b, UNIV, PRIM, INTEGER_TAG_CODE);
    totalLen += l;

  return totalLen;
} // RSAPublicKey::BEncContent


void RSAPublicKey::BDecContent (BUF_TYPE b, AsnTag /*tag0*/, AsnLen elmtLen0, AsnLen &bytesDecoded, ENV_TYPE env)
{
  AsnTag tag1;
  AsnLen seqBytesDecoded = 0;
  AsnLen elmtLen1;
  tag1 = BDecTag (b, seqBytesDecoded, env);

  if ((tag1 == MAKE_TAG_ID (UNIV, PRIM, INTEGER_TAG_CODE))
    || (tag1 == MAKE_TAG_ID (UNIV, CONS, INTEGER_TAG_CODE)))
  {
    elmtLen1 = BDecLen (b, seqBytesDecoded, env);
    modulus.BDecContent (b, tag1, elmtLen1, seqBytesDecoded, env);
    tag1 = BDecTag (b, seqBytesDecoded, env);
  }
  else
  {
    Asn1Error << "ERROR - SEQUENCE is missing non-optional elmt." << endl;
    SnaccExcep::throwMe(-100);
  }

  if ((tag1 == MAKE_TAG_ID (UNIV, PRIM, INTEGER_TAG_CODE))
    || (tag1 == MAKE_TAG_ID (UNIV, CONS, INTEGER_TAG_CODE)))
  {
    elmtLen1 = BDecLen (b, seqBytesDecoded, env);
    publicExponent.BDecContent (b, tag1, elmtLen1, seqBytesDecoded, env);
  }
  else
  {
    Asn1Error << "ERROR - SEQUENCE is missing non-optional elmt." << endl;
    SnaccExcep::throwMe(-101);
  }

  bytesDecoded += seqBytesDecoded;
  if (elmtLen0 == INDEFINITE_LEN)
  {
    BDecEoc (b, bytesDecoded, env);
    return;
  }
  else if (seqBytesDecoded != elmtLen0)
  {
    Asn1Error << "ERROR - Length discrepancy on sequence." << endl;
    SnaccExcep::throwMe(-102);
  }
  else
    return;
} // RSAPublicKey::BDecContent

AsnLen RSAPublicKey::BEnc (BUF_TYPE b)
{
  AsnLen l;
  l = BEncContent (b);
  l += BEncConsLen (b, l);
  l += BEncTag1 (b, UNIV, CONS, SEQ_TAG_CODE);
  return l;
}

void RSAPublicKey::BDec (BUF_TYPE b, AsnLen &bytesDecoded, ENV_TYPE env)
{
  AsnTag tag;
  AsnLen elmtLen1;

  if ((tag = BDecTag (b, bytesDecoded, env)) != MAKE_TAG_ID (UNIV, CONS, SEQ_TAG_CODE))
  {
    Asn1Error << "RSAPublicKey::BDec: ERROR - wrong tag" << endl;
    SnaccExcep::throwMe(-103);
  }
  elmtLen1 = BDecLen (b, bytesDecoded, env);
  BDecContent (b, tag, elmtLen1, bytesDecoded, env);
}

void RSAPublicKey::Print (ostream &os) const
{
#ifndef NDEBUG
  os << "{ -- SEQUENCE --" << endl;
  indentG += stdIndentG;

  {
    Indent (os, indentG);
    os << "modulus ";
    os << modulus;
    os << "," << endl;
  }

  {
    Indent (os, indentG);
    os << "publicExponent ";
    os << publicExponent;
  }

  os << endl;
  indentG -= stdIndentG;
  Indent (os, indentG);
  os << "}";
#endif /* NDEBUG */
} // RSAPublicKey::Print


RSAPrivateKey::RSAPrivateKey()
{
}

RSAPrivateKey::RSAPrivateKey (const RSAPrivateKey &)
{
  Asn1Error << "use of incompletely defined RSAPrivateKey::RSAPrivateKey (const RSAPrivateKey &)" << endl;
  abort();
}

RSAPrivateKey::~RSAPrivateKey()
{
}

AsnType *RSAPrivateKey::Clone() const
{
  return new RSAPrivateKey;
}

AsnType *RSAPrivateKey::Copy() const
{
  return new RSAPrivateKey (*this);
}

#if SNACC_DEEP_COPY
RSAPrivateKey &RSAPrivateKey::operator = (const RSAPrivateKey &that)
#else // SNACC_DEEP_COPY
RSAPrivateKey &RSAPrivateKey::operator = (const RSAPrivateKey &)
#endif // SNACC_DEEP_COPY
{
#if SNACC_DEEP_COPY
  if (this != &that)
  {
    version = that.version;
    modulus = that.modulus;
    publicExponent = that.publicExponent;
    privateExponent = that.privateExponent;
    prime1 = that.prime1;
    prime2 = that.prime2;
    exponent1 = that.exponent1;
    exponent2 = that.exponent2;
    coefficient = that.coefficient;
  }

  return *this;
#else // SNACC_DEEP_COPY
  Asn1Error << "use of incompletely defined RSAPrivateKey &RSAPrivateKey::operator = (const RSAPrivateKey &)" << endl;
  abort();
  // if your compiler complains here, check the -novolat option
#endif // SNACC_DEEP_COPY
}

AsnLen
RSAPrivateKey::BEncContent (BUF_TYPE b)
{
  AsnLen totalLen = 0;
  AsnLen l;

    l = coefficient.BEncContent (b);
    l += BEncDefLen (b, l);

    l += BEncTag1 (b, UNIV, PRIM, INTEGER_TAG_CODE);
    totalLen += l;

    l = exponent2.BEncContent (b);
    l += BEncDefLen (b, l);

    l += BEncTag1 (b, UNIV, PRIM, INTEGER_TAG_CODE);
    totalLen += l;

    l = exponent1.BEncContent (b);
    l += BEncDefLen (b, l);

    l += BEncTag1 (b, UNIV, PRIM, INTEGER_TAG_CODE);
    totalLen += l;

    l = prime2.BEncContent (b);
    l += BEncDefLen (b, l);

    l += BEncTag1 (b, UNIV, PRIM, INTEGER_TAG_CODE);
    totalLen += l;

    l = prime1.BEncContent (b);
    l += BEncDefLen (b, l);

    l += BEncTag1 (b, UNIV, PRIM, INTEGER_TAG_CODE);
    totalLen += l;

    l = privateExponent.BEncContent (b);
    l += BEncDefLen (b, l);

    l += BEncTag1 (b, UNIV, PRIM, INTEGER_TAG_CODE);
    totalLen += l;

    l = publicExponent.BEncContent (b);
    l += BEncDefLen (b, l);

    l += BEncTag1 (b, UNIV, PRIM, INTEGER_TAG_CODE);
    totalLen += l;

    l = modulus.BEncContent (b);
    l += BEncDefLen (b, l);

    l += BEncTag1 (b, UNIV, PRIM, INTEGER_TAG_CODE);
    totalLen += l;

    l = version.BEncContent (b);
    BEncDefLenTo127 (b, l);
    l++;

    l += BEncTag1 (b, UNIV, PRIM, INTEGER_TAG_CODE);
    totalLen += l;

  return totalLen;
} // RSAPrivateKey::BEncContent


void RSAPrivateKey::BDecContent (BUF_TYPE b, AsnTag /*tag0*/, AsnLen elmtLen0, AsnLen &bytesDecoded, ENV_TYPE env)
{
  AsnTag tag1;
  AsnLen seqBytesDecoded = 0;
  AsnLen elmtLen1;
  tag1 = BDecTag (b, seqBytesDecoded, env);

  if ((tag1 == MAKE_TAG_ID (UNIV, PRIM, INTEGER_TAG_CODE)))
  {
    elmtLen1 = BDecLen (b, seqBytesDecoded, env);
    version.BDecContent (b, tag1, elmtLen1, seqBytesDecoded, env);
    tag1 = BDecTag (b, seqBytesDecoded, env);
  }
  else
  {
    Asn1Error << "ERROR - SEQUENCE is missing non-optional elmt." << endl;
    SnaccExcep::throwMe(-104);
  }

  if ((tag1 == MAKE_TAG_ID (UNIV, PRIM, INTEGER_TAG_CODE))
    || (tag1 == MAKE_TAG_ID (UNIV, CONS, INTEGER_TAG_CODE)))
  {
    elmtLen1 = BDecLen (b, seqBytesDecoded, env);
    modulus.BDecContent (b, tag1, elmtLen1, seqBytesDecoded, env);
    tag1 = BDecTag (b, seqBytesDecoded, env);
  }
  else
  {
    Asn1Error << "ERROR - SEQUENCE is missing non-optional elmt." << endl;
    SnaccExcep::throwMe(-105);
  }

  if ((tag1 == MAKE_TAG_ID (UNIV, PRIM, INTEGER_TAG_CODE))
    || (tag1 == MAKE_TAG_ID (UNIV, CONS, INTEGER_TAG_CODE)))
  {
    elmtLen1 = BDecLen (b, seqBytesDecoded, env);
    publicExponent.BDecContent (b, tag1, elmtLen1, seqBytesDecoded, env);
    tag1 = BDecTag (b, seqBytesDecoded, env);
  }
  else
  {
    Asn1Error << "ERROR - SEQUENCE is missing non-optional elmt." << endl;
    SnaccExcep::throwMe(-106);
  }

  if ((tag1 == MAKE_TAG_ID (UNIV, PRIM, INTEGER_TAG_CODE))
    || (tag1 == MAKE_TAG_ID (UNIV, CONS, INTEGER_TAG_CODE)))
  {
    elmtLen1 = BDecLen (b, seqBytesDecoded, env);
    privateExponent.BDecContent (b, tag1, elmtLen1, seqBytesDecoded, env);
    tag1 = BDecTag (b, seqBytesDecoded, env);
  }
  else
  {
    Asn1Error << "ERROR - SEQUENCE is missing non-optional elmt." << endl;
    SnaccExcep::throwMe(-107);
  }

  if ((tag1 == MAKE_TAG_ID (UNIV, PRIM, INTEGER_TAG_CODE))
    || (tag1 == MAKE_TAG_ID (UNIV, CONS, INTEGER_TAG_CODE)))
  {
    elmtLen1 = BDecLen (b, seqBytesDecoded, env);
    prime1.BDecContent (b, tag1, elmtLen1, seqBytesDecoded, env);
    tag1 = BDecTag (b, seqBytesDecoded, env);
  }
  else
  {
    Asn1Error << "ERROR - SEQUENCE is missing non-optional elmt." << endl;
    SnaccExcep::throwMe(-108);
  }

  if ((tag1 == MAKE_TAG_ID (UNIV, PRIM, INTEGER_TAG_CODE))
    || (tag1 == MAKE_TAG_ID (UNIV, CONS, INTEGER_TAG_CODE)))
  {
    elmtLen1 = BDecLen (b, seqBytesDecoded, env);
    prime2.BDecContent (b, tag1, elmtLen1, seqBytesDecoded, env);
    tag1 = BDecTag (b, seqBytesDecoded, env);
  }
  else
  {
    Asn1Error << "ERROR - SEQUENCE is missing non-optional elmt." << endl;
    SnaccExcep::throwMe(-109);
  }

  if ((tag1 == MAKE_TAG_ID (UNIV, PRIM, INTEGER_TAG_CODE))
    || (tag1 == MAKE_TAG_ID (UNIV, CONS, INTEGER_TAG_CODE)))
  {
    elmtLen1 = BDecLen (b, seqBytesDecoded, env);
    exponent1.BDecContent (b, tag1, elmtLen1, seqBytesDecoded, env);
    tag1 = BDecTag (b, seqBytesDecoded, env);
  }
  else
  {
    Asn1Error << "ERROR - SEQUENCE is missing non-optional elmt." << endl;
    SnaccExcep::throwMe(-110);
  }

  if ((tag1 == MAKE_TAG_ID (UNIV, PRIM, INTEGER_TAG_CODE))
    || (tag1 == MAKE_TAG_ID (UNIV, CONS, INTEGER_TAG_CODE)))
  {
    elmtLen1 = BDecLen (b, seqBytesDecoded, env);
    exponent2.BDecContent (b, tag1, elmtLen1, seqBytesDecoded, env);
    tag1 = BDecTag (b, seqBytesDecoded, env);
  }
  else
  {
    Asn1Error << "ERROR - SEQUENCE is missing non-optional elmt." << endl;
    SnaccExcep::throwMe(-111);
  }

  if ((tag1 == MAKE_TAG_ID (UNIV, PRIM, INTEGER_TAG_CODE))
    || (tag1 == MAKE_TAG_ID (UNIV, CONS, INTEGER_TAG_CODE)))
  {
    elmtLen1 = BDecLen (b, seqBytesDecoded, env);
    coefficient.BDecContent (b, tag1, elmtLen1, seqBytesDecoded, env);
  }
  else
  {
    Asn1Error << "ERROR - SEQUENCE is missing non-optional elmt." << endl;
    SnaccExcep::throwMe(-112);
  }

  bytesDecoded += seqBytesDecoded;
  if (elmtLen0 == INDEFINITE_LEN)
  {
    BDecEoc (b, bytesDecoded, env);
    return;
  }
  else if (seqBytesDecoded != elmtLen0)
  {
    Asn1Error << "ERROR - Length discrepancy on sequence." << endl;
    SnaccExcep::throwMe(-113);
  }
  else
    return;
} // RSAPrivateKey::BDecContent

AsnLen RSAPrivateKey::BEnc (BUF_TYPE b)
{
  AsnLen l;
  l = BEncContent (b);
  l += BEncConsLen (b, l);
  l += BEncTag1 (b, UNIV, CONS, SEQ_TAG_CODE);
  return l;
}

void RSAPrivateKey::BDec (BUF_TYPE b, AsnLen &bytesDecoded, ENV_TYPE env)
{
  AsnTag tag;
  AsnLen elmtLen1;

  if ((tag = BDecTag (b, bytesDecoded, env)) != MAKE_TAG_ID (UNIV, CONS, SEQ_TAG_CODE))
  {
    Asn1Error << "RSAPrivateKey::BDec: ERROR - wrong tag" << endl;
    SnaccExcep::throwMe(-114);
  }
  elmtLen1 = BDecLen (b, bytesDecoded, env);
  BDecContent (b, tag, elmtLen1, bytesDecoded, env);
}

void RSAPrivateKey::Print (ostream &os) const
{
#ifndef NDEBUG
  os << "{ -- SEQUENCE --" << endl;
  indentG += stdIndentG;

  {
    Indent (os, indentG);
    os << "version ";
    os << version;
    os << "," << endl;
  }

  {
    Indent (os, indentG);
    os << "modulus ";
    os << modulus;
    os << "," << endl;
  }

  {
    Indent (os, indentG);
    os << "publicExponent ";
    os << publicExponent;
    os << "," << endl;
  }

  {
    Indent (os, indentG);
    os << "privateExponent ";
    os << privateExponent;
    os << "," << endl;
  }

  {
    Indent (os, indentG);
    os << "prime1 ";
    os << prime1;
    os << "," << endl;
  }

  {
    Indent (os, indentG);
    os << "prime2 ";
    os << prime2;
    os << "," << endl;
  }

  {
    Indent (os, indentG);
    os << "exponent1 ";
    os << exponent1;
    os << "," << endl;
  }

  {
    Indent (os, indentG);
    os << "exponent2 ";
    os << exponent2;
    os << "," << endl;
  }

  {
    Indent (os, indentG);
    os << "coefficient ";
    os << coefficient;
  }

  os << endl;
  indentG -= stdIndentG;
  Indent (os, indentG);
  os << "}";
#endif /* NDEBUG */
} // RSAPrivateKey::Print

