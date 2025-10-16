/*
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape security libraries.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1994-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Contributor(s):
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 */

/*
 * Support for DEcoding ASN.1 data based on BER/DER (Basic/Distinguished
 * Encoding Rules).
 *
 * $Id: secasn1d.c,v 1.16 2004/05/13 15:29:13 dmitch Exp $
 */
#include <limits.h>

#include <security_utilities/simulatecrash_assert.h>
#include "secasn1.h"
#include "secerr.h"

#ifdef NDEBUG
#define DEBUG_DECASN1 0
#else
#define DEBUG_DECASN1 1
#endif

#if DEBUG_DECASN1
#include <stdio.h>
#define dprintf(args...) printf(args)
#else
#define dprintf(args...)
#endif /* DEBUG_DECASN1 */

typedef enum {
    beforeIdentifier,
    duringIdentifier,
    afterIdentifier,
    beforeLength,
    duringLength,
    afterLength,
    beforeBitString,
    duringBitString,
    duringConstructedString,
    duringGroup,
    duringLeaf,
    duringSaveEncoding,
    duringSequence,
    afterConstructedString,
    afterGroup,
    afterExplicit,
    afterImplicit,
    afterInline,
    afterPointer,
    afterSaveEncoding,
    beforeEndOfContents,
    duringEndOfContents,
    afterEndOfContents,
    beforeChoice,
    duringChoice,
    afterChoice,
    notInUse
} sec_asn1d_parse_place;

#ifndef NDEBUG
#define DEBUG_ASN1D_STATES 1
/* tweakable by debugger, debug only */
int doDumpStates = 0;
#else  /* DEBUG_ASN1D_STATES 0 */
#endif /* DEBUG_ASN1D_STATES */

#if DEBUG_ASN1D_STATES
static const char* place_names[] = {"beforeIdentifier",
                                    "duringIdentifier",
                                    "afterIdentifier",
                                    "beforeLength",
                                    "duringLength",
                                    "afterLength",
                                    "beforeBitString",
                                    "duringBitString",
                                    "duringConstructedString",
                                    "duringGroup",
                                    "duringLeaf",
                                    "duringSaveEncoding",
                                    "duringSequence",
                                    "afterConstructedString",
                                    "afterGroup",
                                    "afterExplicit",
                                    "afterImplicit",
                                    "afterInline",
                                    "afterPointer",
                                    "afterSaveEncoding",
                                    "beforeEndOfContents",
                                    "duringEndOfContents",
                                    "afterEndOfContents",
                                    "beforeChoice",
                                    "duringChoice",
                                    "afterChoice",
                                    "notInUse"};

static const char* const class_names[] = {"UNIVERSAL", "APPLICATION", "CONTEXT_SPECIFIC", "PRIVATE"};

static const char* const method_names[] = {"PRIMITIVE", "CONSTRUCTED"};

static const char* const type_names[] = {"END_OF_CONTENTS",  "BOOLEAN",
                                         "INTEGER",          "BIT_STRING",
                                         "OCTET_STRING",     "NULL",
                                         "OBJECT_ID",        "OBJECT_DESCRIPTOR",
                                         "(type 08)",        "REAL",
                                         "ENUMERATED",       "EMBEDDED",
                                         "UTF8_STRING",      "(type 0d)",
                                         "(type 0e)",        "(type 0f)",
                                         "SEQUENCE",         "SET",
                                         "NUMERIC_STRING",   "PRINTABLE_STRING",
                                         "T61_STRING",       "VIDEOTEXT_STRING",
                                         "IA5_STRING",       "UTC_TIME",
                                         "GENERALIZED_TIME", "GRAPHIC_STRING",
                                         "VISIBLE_STRING",   "GENERAL_STRING",
                                         "UNIVERSAL_STRING", "(type 1d)",
                                         "BMP_STRING",       "HIGH_TAG_VALUE"};

static const char* const flag_names[] = {/* flags, right to left */
                                         "OPTIONAL",    "EXPLICIT",   "ANY",
                                         "INLINE",      "POINTER",    "GROUP",
                                         "DYNAMIC",     "SKIP",       "INNER",
                                         "SAVE",        "", /* decoder ignores "MAY_STREAM", */
                                         "SKIP_REST",   "CHOICE",     "NO_STREAM",
                                         "DEBUG_BREAK", "unknown 08", "unknown 10",
                                         "unknown 20",  "unknown 40", "unknown 80"};

static int /* bool */
formatKind(unsigned long kind, char* buf, size_t buf_sz)
{
    int i;
    unsigned long k = kind & SEC_ASN1_TAGNUM_MASK;
    unsigned long notag = kind & (SEC_ASN1_CHOICE | SEC_ASN1_POINTER | SEC_ASN1_INLINE |
                                  SEC_ASN1_ANY | SEC_ASN1_SAVE);

    buf[0] = 0;
    if ((kind & SEC_ASN1_CLASS_MASK) != SEC_ASN1_UNIVERSAL) {
        snprintf(buf, buf_sz, " %s", class_names[(kind & SEC_ASN1_CLASS_MASK) >> 6]);
        buf_sz -= strlen(buf);
        buf += strlen(buf);
    }
    if (kind & SEC_ASN1_METHOD_MASK) {
        snprintf(buf, buf_sz, " %s", method_names[1]);
        buf_sz -= strlen(buf);
        buf += strlen(buf);
    }
    if ((kind & SEC_ASN1_CLASS_MASK) == SEC_ASN1_UNIVERSAL) {
        if (k || !notag) {
            snprintf(buf, buf_sz, " %s", type_names[k]);
            buf_sz -= strlen(buf);
            buf += strlen(buf);
            if ((k == SEC_ASN1_SET || k == SEC_ASN1_SEQUENCE) && (kind & SEC_ASN1_GROUP)) {
                snprintf(buf, buf_sz, "_OF");
                buf_sz -= strlen(buf);
                buf += strlen(buf);
            }
        }
    } else {
        snprintf(buf, buf_sz, " [%lu]", k);
        buf_sz -= strlen(buf);
        buf += strlen(buf);
    }

    for (k = kind >> 8, i = 0; k; k >>= 1, ++i) {
        if (k & 1) {
            snprintf(buf, buf_sz, " %s", flag_names[i]);
            buf_sz -= strlen(buf);
            buf += strlen(buf);
        }
    }
    return notag != 0;
}

#endif /* DEBUG_ASN1D_STATES */

typedef enum { allDone, decodeError, keepGoing, needBytes } sec_asn1d_parse_status;

struct subitem {
    const void* data;
    unsigned long len; /* only used for substrings */
    struct subitem* next;
};

typedef struct sec_asn1d_state_struct {
    SEC_ASN1DecoderContext* top;
    const SecAsn1Template* theTemplate;
    void* dest;

    void* our_mark; /* free on completion */

    struct sec_asn1d_state_struct* parent; /* aka prev */
    struct sec_asn1d_state_struct* child;  /* aka next */

    sec_asn1d_parse_place place;

    /*
     * XXX explain the next fields as clearly as possible...
     */
    unsigned char found_tag_modifiers;
    unsigned char expect_tag_modifiers;
    unsigned long check_tag_mask;
    unsigned long found_tag_number;
    unsigned long expect_tag_number;
    unsigned long underlying_kind;

    unsigned long contents_length;
    unsigned long pending;
    unsigned long consumed;

    int depth;

    /*
     * Bit strings have their length adjusted -- the first octet of the
     * contents contains a value between 0 and 7 which says how many bits
     * at the end of the octets are not actually part of the bit string;
     * when parsing bit strings we put that value here because we need it
     * later, for adjustment of the length (when the whole string is done).
     */
    unsigned int bit_string_unused_bits;

    /*
     * The following are used for indefinite-length constructed strings.
     */
    struct subitem* subitems_head;
    struct subitem* subitems_tail;

    PRPackedBool allocate, /* when true, need to allocate the destination */
        endofcontents,     /* this state ended up parsing end-of-contents octets */
        explicit,          /* we are handling an explicit header */
        indefinite,        /* the current item has indefinite-length encoding */
        missing,           /* an optional field that was not present */
        optional,          /* the template says this field may be omitted */
        substring;         /* this is a substring of a constructed string */
} sec_asn1d_state;

#define IS_HIGH_TAG_NUMBER(n) ((n) == SEC_ASN1_HIGH_TAG_NUMBER)
#define LAST_TAG_NUMBER_BYTE(b) (((b)&0x80) == 0)
#define TAG_NUMBER_BITS 7
#define TAG_NUMBER_MASK 0x7f

#define LENGTH_IS_SHORT_FORM(b) (((b)&0x80) == 0)
#define LONG_FORM_LENGTH(b) ((b)&0x7f)

#define HIGH_BITS(field, cnt) ((field) >> ((sizeof(field) * 8) - (cnt)))


/*
 * An "outsider" will have an opaque pointer to this, created by calling
 * SEC_ASN1DecoderStart().  It will be passed back in to all subsequent
 * calls to SEC_ASN1DecoderUpdate(), and when done it is passed to
 * SEC_ASN1DecoderFinish().
 */
struct sec_DecoderContext_struct {
    PRArenaPool* our_pool;     /* for our internal allocs */
    PRArenaPool* their_pool;   /* for destination structure allocs */
#ifdef SEC_ASN1D_FREE_ON_ERROR /*
					 * XXX see comment below (by same
					 * ifdef) that explains why this
					 * does not work (need more smarts
					 * in order to free back to mark)
					 */
    /*
     * XXX how to make their_mark work in the case where they do NOT
     * give us a pool pointer?
     */
    void* their_mark; /* free on error */
#endif

    sec_asn1d_state* current;
    sec_asn1d_parse_status status;

    SEC_ASN1NotifyProc notify_proc; /* call before/after handling field */
    void* notify_arg;               /* argument to notify_proc */
    PRBool during_notify;           /* true during call to notify_proc */

    SEC_ASN1WriteProc filter_proc; /* pass field bytes to this  */
    void* filter_arg;              /* argument to that function */
    PRBool filter_only;            /* do not allocate/store fields */
};


/*
 * XXX this is a fairly generic function that may belong elsewhere
 */
static void* sec_asn1d_alloc(PRArenaPool* poolp, unsigned long len)
{
    void* thing;

    if (poolp != NULL) {
        /*
		* Allocate from the pool.
		*/
        thing = PORT_ArenaAlloc(poolp, len);
    } else {
        /*
		* Allocate generically.
		*/
        thing = PORT_Alloc(len);
    }

    return thing;
}


/*
 * XXX this is a fairly generic function that may belong elsewhere
 */
static void* sec_asn1d_zalloc(PRArenaPool* poolp, unsigned long len)
{
    void* thing;

    thing = sec_asn1d_alloc(poolp, len);
    if (thing != NULL) {
        PORT_Memset(thing, 0, len);
    }
    return thing;
}


static sec_asn1d_state* sec_asn1d_push_state(SEC_ASN1DecoderContext* cx,
                                             const SecAsn1Template* theTemplate,
                                             void* dest,
                                             PRBool new_depth)
{
    sec_asn1d_state *state, *new_state = NULL;

    state = cx->current;

    PORT_Assert(state == NULL || state->child == NULL);

    if (theTemplate == NULL) {
        PORT_SetError (SEC_ERROR_BAD_TEMPLATE);
        goto loser;
    }

    if (state != NULL) {
        PORT_Assert(state->our_mark == NULL);
        state->our_mark = PORT_ArenaMark(cx->our_pool);
    }

    new_state = (sec_asn1d_state*)sec_asn1d_zalloc(cx->our_pool, sizeof(*new_state));
    if (new_state == NULL) {
        dprintf("decodeError: zalloc failure\n");
        goto loser;
    }

    new_state->top = cx;
    new_state->parent = state;
    new_state->theTemplate = theTemplate;
    new_state->place = notInUse;
    if (dest != NULL) {
        new_state->dest = (char*)dest + theTemplate->offset;
    }

    if (state != NULL) {
        new_state->depth = state->depth;
        if (new_depth) {
            if (++new_state->depth > SEC_ASN1D_MAX_DEPTH) {
                PORT_SetError(SEC_ERROR_BAD_DER);
                goto loser;
            }
        }
        state->child = new_state;
    }

    cx->current = new_state;
    return new_state;

loser:
    cx->status = decodeError;
    if (state != NULL) {
        PORT_ArenaRelease(cx->our_pool, state->our_mark);
        state->our_mark = NULL;
    }
    return NULL;
}


static void sec_asn1d_scrub_state(sec_asn1d_state* state)
{
    /*
     * Some default "scrubbing".
     * XXX right set of initializations?
     */
    state->place = beforeIdentifier;
    state->endofcontents = PR_FALSE;
    state->indefinite = PR_FALSE;
    state->missing = PR_FALSE;

    PORT_Assert(state->consumed == 0);
}


static sec_asn1d_state* sec_asn1d_get_enclosing_construct(sec_asn1d_state* state)
{
    for (state = state->parent; state; state = state->parent) {
        sec_asn1d_parse_place place = state->place;
        if (place != afterImplicit && place != afterPointer && place != afterInline &&
            place != afterSaveEncoding && place != duringSaveEncoding && place != duringChoice) {
            /* we've walked up the stack to a state that represents
            ** the enclosing construct.  
            */
            break;
        }
    }
    return state;
}


static PRBool sec_asn1d_parent_allows_EOC(sec_asn1d_state* state)
{
    /* get state of enclosing construct. */
    state = sec_asn1d_get_enclosing_construct(state);
    if (state) {
        sec_asn1d_parse_place place = state->place;
        /* Is it one of the types that permits an unexpected EOC? */
        int eoc_permitted =
            (place == duringGroup || place == duringConstructedString || state->child->optional);
        return (state->indefinite && eoc_permitted) ? PR_TRUE : PR_FALSE;
    }
    return PR_FALSE;
}


static void sec_asn1d_notify_before(SEC_ASN1DecoderContext* cx, void* dest, int depth)
{
    if (cx->notify_proc == NULL)
        return;

    cx->during_notify = PR_TRUE;
    (*cx->notify_proc)(cx->notify_arg, PR_TRUE, dest, depth);
    cx->during_notify = PR_FALSE;
}


static void sec_asn1d_notify_after(SEC_ASN1DecoderContext* cx, void* dest, int depth)
{
    if (cx->notify_proc == NULL)
        return;

    cx->during_notify = PR_TRUE;
    (*cx->notify_proc)(cx->notify_arg, PR_FALSE, dest, depth);
    cx->during_notify = PR_FALSE;
}


static sec_asn1d_state* sec_asn1d_init_state_based_on_template(sec_asn1d_state* state,
#ifdef __APPLE__
                                                               const char* buf, /* for SEC_ASN1GetSubtemplate() */
                                                               size_t len
#endif
)
{
    PRBool explicit, optional, universal;
    unsigned char expect_tag_modifiers;
    unsigned long encode_kind, under_kind;
    unsigned long check_tag_mask, expect_tag_number;
#ifdef __APPLE__
    unsigned long dynamic;
#endif


    /* XXX Check that both of these tests are really needed/appropriate. */
    if (state == NULL || state->top->status == decodeError || state->theTemplate == NULL)
        return state;

    encode_kind = state->theTemplate->kind;

    if (encode_kind & SEC_ASN1_SAVE) {
        /*
		* This is a "magic" field that saves away all bytes, allowing
		* the immediately following field to still be decoded from this
		* same spot -- sort of a fork.
		*/
        /* check that there are no extraneous bits */
        PORT_Assert(encode_kind == SEC_ASN1_SAVE);
        if (state->top->filter_only) {
            /*
			* If we are not storing, then we do not do the SAVE field
			* at all.  Just move ahead to the "real" field instead,
			* doing the appropriate notify calls before and after.
			*/
            sec_asn1d_notify_after(state->top, state->dest, state->depth);
            /*
			* Since we are not storing, allow for our current dest value
			* to be NULL.  (This might not actually occur, but right now I
			* cannot convince myself one way or the other.)  If it is NULL,
			* assume that our parent dest can help us out.
			*/
            if (state->dest == NULL) {
                state->dest = state->parent->dest;
            } else {
                state->dest = (char*)state->dest - state->theTemplate->offset;
            }
            state->theTemplate++;
            if (state->dest != NULL) {
                state->dest = (char*)state->dest + state->theTemplate->offset;
            }
            sec_asn1d_notify_before(state->top, state->dest, state->depth);
            encode_kind = state->theTemplate->kind;
            PORT_Assert((encode_kind & SEC_ASN1_SAVE) == 0);
        } else {
            sec_asn1d_scrub_state(state);
            state->place = duringSaveEncoding;
            state = sec_asn1d_push_state(state->top, kSecAsn1AnyTemplate, state->dest, PR_FALSE);
            if (state != NULL) {
                state = sec_asn1d_init_state_based_on_template(
                    state, buf /* __APPLE__ */, len /* __APPLE__ */);
            }
            return state;
        }
    }


    universal = ((encode_kind & SEC_ASN1_CLASS_MASK) == SEC_ASN1_UNIVERSAL) ? PR_TRUE : PR_FALSE;

    explicit = (encode_kind & SEC_ASN1_EXPLICIT) ? PR_TRUE : PR_FALSE;
    encode_kind &= (unsigned long)~SEC_ASN1_EXPLICIT;

    optional = (encode_kind & SEC_ASN1_OPTIONAL) ? PR_TRUE : PR_FALSE;
    encode_kind &= (unsigned long)~SEC_ASN1_OPTIONAL;

#ifdef __APPLE__
    dynamic = (encode_kind & SEC_ASN1_DYNAMIC) ? PR_TRUE : PR_FALSE;
    encode_kind &= (unsigned long)~SEC_ASN1_DYNAMIC;
#endif

    PORT_Assert(!(explicit && universal)); /* bad templates */

    encode_kind &= (unsigned long)~SEC_ASN1_DYNAMIC;
    encode_kind &= (unsigned long)~SEC_ASN1_MAY_STREAM;

    if (encode_kind & SEC_ASN1_CHOICE) {
#if 0 /* XXX remove? */
      sec_asn1d_state *child = sec_asn1d_push_state(state->top, state->theTemplate, state->dest, PR_FALSE);
      if( (sec_asn1d_state *)NULL == child ) {
        return (sec_asn1d_state *)NULL;
      }

      child->allocate = state->allocate;
      child->place = beforeChoice;
      return child;
#else
        state->place = beforeChoice;
        return state;
#endif
    }

    if ((encode_kind & (SEC_ASN1_POINTER | SEC_ASN1_INLINE)) || (!universal && !explicit)) {
        const SecAsn1Template* subt;
        void* dest;
        PRBool child_allocate;
        void* subDest;

        PORT_Assert((encode_kind & (SEC_ASN1_ANY | SEC_ASN1_SKIP)) == 0);

        sec_asn1d_scrub_state(state);
        child_allocate = PR_FALSE;

        if (encode_kind & SEC_ASN1_POINTER) {
            /*
			* A POINTER means we need to allocate the destination for
			* this field.  But, since it may also be an optional field,
			* we defer the allocation until later; we just record that
			* it needs to be done.
			*
			* There are two possible scenarios here -- one is just a
			* plain POINTER (kind of like INLINE, except with allocation)
			* and the other is an implicitly-tagged POINTER.  We don't
			* need to do anything special here for the two cases, but
			* since the template definition can be tricky, we do check
			* that there are no extraneous bits set in encode_kind.
			*
			* XXX The same conditions which assert should set an error.
			*/
            if (universal) {
                /*
				 * "universal" means this entry is a standalone POINTER;
				 * there should be no other bits set in encode_kind.
				 */
                PORT_Assert(encode_kind == SEC_ASN1_POINTER);
            } else {
                /*
				 * If we get here we have an implicitly-tagged field
				 * that needs to be put into a POINTER.  The subtemplate
				 * will determine how to decode the field, but encode_kind
				 * describes the (implicit) tag we are looking for.
				 * The non-tag bits of encode_kind will be ignored by
				 * the code below; none of them should be set, however,
				 * except for the POINTER bit itself -- so check that.
				 */
                PORT_Assert((encode_kind & (unsigned long)~SEC_ASN1_TAG_MASK) == SEC_ASN1_POINTER);
            }
            if (!state->top->filter_only)
                child_allocate = PR_TRUE;
            dest = NULL;
            state->place = afterPointer;
        } else {
            dest = state->dest;
            if (encode_kind & SEC_ASN1_INLINE) {
                /* check that there are no extraneous bits */
                /* FIXME - why are optional and inline mutually 
				 * exclusive? Delete this assert and see what happens...
				PORT_Assert (encode_kind == SEC_ASN1_INLINE && !optional);
				*/
                state->place = afterInline;
            } else {
                state->place = afterImplicit;
            }
        }

        state->optional = optional;

        subDest = state->dest;
#if defined(__APPLE__)
        /*
		 * We might be starting the processing of a group or a
		 * set, in which case state->dest is NULL. Get parent's dest,
		 * or grandparent's, etc... just for the use by 
		 * SEC_ASN1GetSubtemplate (specifically, by dynamic
		 * choosers)
		 */
        sec_asn1d_state* tempState = state;
        while (subDest == NULL) {
            sec_asn1d_state* parent = tempState->parent;
            if (parent == NULL) {
                /* Oh well. Not going to work for this template. */
                break;
            }
            subDest = parent->dest;
            tempState = parent;
        }
#endif /* __APPLE__ */
        subt = SEC_ASN1GetSubtemplate(
            state->theTemplate, subDest, PR_FALSE, buf /* __APPLE__ */, len /* __APPLE__ */);
        state = sec_asn1d_push_state(state->top, subt, dest, PR_FALSE);
        if (state == NULL) {
            return NULL;
        }

        state->allocate = child_allocate;

        if (universal
#ifdef __APPLE__
            /* Dynamic: restart with new template */
            || dynamic
#endif
        ) {
            state = sec_asn1d_init_state_based_on_template(state, buf /* __APPLE__ */, len /* __APPLE__ */);
            if (state != NULL) {
                /*
				 * If this field is optional, we need to record that on
				 * the pushed child so it won't fail if the field isn't
				 * found.  I can't think of a way that this new state
				 * could already have optional set (which we would wipe
				 * out below if our local optional is not set) -- but
				 * just to be sure, assert that it isn't set.
				 */
                PORT_Assert(!state->optional);
                state->optional = optional;
            }
            return state;
        }

        under_kind = state->theTemplate->kind;
        under_kind &= (unsigned long)~SEC_ASN1_MAY_STREAM;
    } else if (explicit) {
        /*
		 * For explicit, we only need to match the encoding tag next,
		 * then we will push another state to handle the entire inner
		 * part.  In this case, there is no underlying kind which plays
		 * any part in the determination of the outer, explicit tag.
		 * So we just set under_kind to 0, which is not a valid tag,
		 * and the rest of the tag matching stuff should be okay.
		 */
        under_kind = 0;
    } else {
        /*
		* Nothing special; the underlying kind and the given encoding
		* information are the same.
		*/
        under_kind = encode_kind;
    }

    /* XXX is this the right set of bits to test here? */
    PORT_Assert((under_kind & (SEC_ASN1_EXPLICIT | SEC_ASN1_MAY_STREAM | SEC_ASN1_INLINE |
                               SEC_ASN1_POINTER)) == 0);

    if (encode_kind & (SEC_ASN1_ANY | SEC_ASN1_SKIP)) {
        PORT_Assert(encode_kind == under_kind);
        if (encode_kind & SEC_ASN1_SKIP) {
            PORT_Assert(!optional);
            PORT_Assert(encode_kind == SEC_ASN1_SKIP);
            state->dest = NULL;
        }
        check_tag_mask = 0;
        expect_tag_modifiers = 0;
        expect_tag_number = 0;
    } else {
        check_tag_mask = SEC_ASN1_TAG_MASK;
        expect_tag_modifiers = (unsigned char)encode_kind & SEC_ASN1_TAG_MASK & ~SEC_ASN1_TAGNUM_MASK;
        /*
		 * XXX This assumes only single-octet identifiers.  To handle
		 * the HIGH TAG form we would need to do some more work, especially
		 * in how to specify them in the template, because right now we
		 * do not provide a way to specify more *tag* bits in encode_kind.
		 */
        expect_tag_number = encode_kind & SEC_ASN1_TAGNUM_MASK;

        switch (under_kind & SEC_ASN1_TAGNUM_MASK) {
            case SEC_ASN1_SET:
                /*
			 * XXX A plain old SET (as opposed to a SET OF) is not 
			 * implemented.
			 * If it ever is, remove this assert...
			 */
                PORT_Assert((under_kind & SEC_ASN1_GROUP) != 0);
                [[fallthrough]];
            case SEC_ASN1_SEQUENCE:
                expect_tag_modifiers |= SEC_ASN1_CONSTRUCTED;
                break;
            case SEC_ASN1_BIT_STRING:
            case SEC_ASN1_BMP_STRING:
            case SEC_ASN1_GENERALIZED_TIME:
            case SEC_ASN1_IA5_STRING:
            case SEC_ASN1_OCTET_STRING:
            case SEC_ASN1_PRINTABLE_STRING:
            case SEC_ASN1_T61_STRING:
            case SEC_ASN1_UNIVERSAL_STRING:
            case SEC_ASN1_UTC_TIME:
            case SEC_ASN1_UTF8_STRING:
            case SEC_ASN1_VISIBLE_STRING:
                check_tag_mask &= (unsigned long)~SEC_ASN1_CONSTRUCTED;
                break;
        }
    }

    state->check_tag_mask = check_tag_mask;
    state->expect_tag_modifiers = expect_tag_modifiers;
    state->expect_tag_number = expect_tag_number;
    state->underlying_kind = under_kind;
    state->explicit = explicit;
    state->optional = optional;
    sec_asn1d_scrub_state(state);

    return state;
}


static unsigned long sec_asn1d_parse_identifier(sec_asn1d_state* state, const char* buf, unsigned long len)
{
    unsigned char byte;
    unsigned char tag_number;

    PORT_Assert(state->place == beforeIdentifier);

    if (len == 0) {
        state->top->status = needBytes;
        return 0;
    }

    byte = (unsigned char)*buf;
#ifdef DEBUG_ASN1D_STATES
    if (doDumpStates > 0) {
        char kindBuf[256];
        formatKind(byte, kindBuf, sizeof(kindBuf));
        printf("Found tag %02x %s\n", byte, kindBuf);
    }
#endif
    tag_number = byte & SEC_ASN1_TAGNUM_MASK;

    if (IS_HIGH_TAG_NUMBER(tag_number)) {
        state->place = duringIdentifier;
        state->found_tag_number = 0;
        /*
		 * Actually, we have no idea how many bytes are pending, but we
		 * do know that it is at least 1.  That is all we know; we have
		 * to look at each byte to know if there is another, etc.
		 */
        state->pending = 1;
    } else {
        if (byte == 0 && sec_asn1d_parent_allows_EOC(state)) {
            /*
			 * Our parent has indefinite-length encoding, and the
			 * entire tag found is 0, so it seems that we have hit the
			 * end-of-contents octets.  To handle this, we just change
			 * our state to that which expects to get the bytes of the
			 * end-of-contents octets and let that code re-read this byte
			 * so that our categorization of field types is correct.
			 * After that, our parent will then deal with everything else.
			 */
            state->place = duringEndOfContents;
            state->pending = 2;
            state->found_tag_number = 0;
            state->found_tag_modifiers = 0;
            /*
			 * We might be an optional field that is, as we now find out,
			 * missing.  Give our parent a clue that this happened.
			 */
            if (state->optional)
                state->missing = PR_TRUE;
            return 0;
        }
        state->place = afterIdentifier;
        state->found_tag_number = tag_number;
    }
    state->found_tag_modifiers = byte & ~SEC_ASN1_TAGNUM_MASK;

    return 1;
}


static unsigned long
sec_asn1d_parse_more_identifier(sec_asn1d_state* state, const char* buf, unsigned long len)
{
    unsigned char byte;
    unsigned long count;

    PORT_Assert(state->pending == 1);
    PORT_Assert(state->place == duringIdentifier);

    if (len == 0) {
        state->top->status = needBytes;
        return 0;
    }

    count = 0;

    while (len && state->pending) {
        if (HIGH_BITS(state->found_tag_number, TAG_NUMBER_BITS) != 0) {
            /*
	     * The given high tag number overflows our container;
	     * just give up.  This is not likely to *ever* happen.
	     */
            PORT_SetError(SEC_ERROR_BAD_DER);
            state->top->status = decodeError;
            dprintf("decodeError: parse_more_id high bits oflow\n");
            return 0;
        }

        state->found_tag_number <<= TAG_NUMBER_BITS;

        byte = (unsigned char)buf[count++];
        state->found_tag_number |= (byte & TAG_NUMBER_MASK);

        len--;
        if (LAST_TAG_NUMBER_BYTE(byte)) {
            state->pending = 0;
        }
    }

    if (state->pending == 0) {
        state->place = afterIdentifier;
    }

    return count;
}


static void sec_asn1d_confirm_identifier(sec_asn1d_state* state)
{
    PRBool match;

    PORT_Assert(state->place == afterIdentifier);

    match = (PRBool)(
        ((state->found_tag_modifiers & state->check_tag_mask) == state->expect_tag_modifiers) &&
        ((state->found_tag_number & state->check_tag_mask) == state->expect_tag_number));
    if (match) {
        state->place = beforeLength;
    } else {
        if (state->optional) {
            state->missing = PR_TRUE;
            state->place = afterEndOfContents;
        } else {
            PORT_SetError(SEC_ERROR_BAD_DER);
            state->top->status = decodeError;
            //dprintf("decodeError: sec_asn1d_confirm_identifier\n");
        }
    }
}


static unsigned long sec_asn1d_parse_length(sec_asn1d_state* state, const char* buf, unsigned long len)
{
    unsigned char byte;

    PORT_Assert(state->place == beforeLength);

    if (len == 0) {
        state->top->status = needBytes;
        return 0;
    }

    /*
     * The default/likely outcome.  It may get adjusted below.
     */
    state->place = afterLength;

    byte = (unsigned char)*buf;

    if (LENGTH_IS_SHORT_FORM(byte)) {
        state->contents_length = byte;
    } else {
        state->contents_length = 0;
        state->pending = LONG_FORM_LENGTH(byte);
        if (state->pending == 0) {
            state->indefinite = PR_TRUE;
        } else {
            state->place = duringLength;
        }
    }

    /* If we're parsing an ANY, SKIP, or SAVE template, and 
        ** the object being saved is definite length encoded and constructed, 
        ** there's no point in decoding that construct's members.
        ** So, just forget it's constructed and treat it as primitive.
        ** (SAVE appears as an ANY at this point)
        */
    if (!state->indefinite && (state->underlying_kind & (SEC_ASN1_ANY | SEC_ASN1_SKIP))) {
        state->found_tag_modifiers &= ~SEC_ASN1_CONSTRUCTED;
    }

    return 1;
}


static unsigned long sec_asn1d_parse_more_length(sec_asn1d_state* state, const char* buf, unsigned long len)
{
    unsigned long count;

    PORT_Assert(state->pending > 0);
    PORT_Assert(state->place == duringLength);

    if (len == 0) {
        state->top->status = needBytes;
        return 0;
    }

    count = 0;

    while (len && state->pending) {
        if (HIGH_BITS(state->contents_length, 9) != 0) {
            /*
			* The given full content length overflows our container;
			* just give up.
			*/
            PORT_SetError(SEC_ERROR_BAD_DER);
            state->top->status = decodeError;
            dprintf("decodeError: sec_asn1d_parse_more_length\n");
            return 0;
        }

        state->contents_length <<= 8;
        state->contents_length |= (unsigned char)buf[count++];

        len--;
        state->pending--;
    }

    if (state->pending == 0) {
        state->place = afterLength;
    }

    return count;
}


/*
 * Helper function for sec_asn1d_prepare_for_contents.
 * Checks that a value representing a number of bytes consumed can be
 * subtracted from a remaining length. If so, returns PR_TRUE.
 * Otherwise, sets the error SEC_ERROR_BAD_DER, indicates that there was a
 * decoding error in the given SEC_ASN1DecoderContext, and returns PR_FALSE.
 */
static PRBool sec_asn1d_check_and_subtract_length(unsigned long* remaining,
                                                  unsigned long consumed,
                                                  SEC_ASN1DecoderContext* cx)
{
    PORT_Assert(remaining);
    PORT_Assert(cx);
    if (!remaining || !cx) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        if (cx) {
            cx->status = decodeError;
        }
        return PR_FALSE;
    }
    if (*remaining < consumed) {
        PORT_SetError(SEC_ERROR_BAD_DER);
        cx->status = decodeError;
        return PR_FALSE;
    }
    *remaining -= consumed;
    return PR_TRUE;
}


static void sec_asn1d_prepare_for_contents(sec_asn1d_state* state,
#ifdef __APPLE__
                                           const char* buf, /* needed for SEC_ASN1GetSubtemplate */
                                           size_t len
#endif
)
{
    SecAsn1Item* item = NULL;
    PRArenaPool* poolp;
    unsigned long alloc_len;

#ifdef DEBUG_ASN1D_STATES
    if (doDumpStates > 0) {
        printf("Found Length %lu %s\n", state->contents_length, state->indefinite ? "indefinite" : "");
    }
#endif

    /**
     * The maximum length for a child element should be constrained to the
     * length remaining in the first definite length element in the ancestor
     * stack. If there is no definite length element in the ancestor stack,
     * there's nothing to constrain the length of the child, so there's no
     * further processing necessary.
     *
     * It's necessary to walk the ancestor stack, because it's possible to have
     * definite length children that are part of an indefinite length element,
     * which is itself part of an indefinite length element, and which is
     * ultimately part of a definite length element. A simple example of this
     * would be the handling of constructed OCTET STRINGs in BER encoding.
     *
     * This algorithm finds the first definite length element in the ancestor
     * stack, if any, and if so, ensures that the length of the child element
     * is consistent with the number of bytes remaining in the constraining
     * ancestor element (that is, after accounting for any other sibling
     * elements that may have been read).
     *
     * It's slightly complicated by the need to account both for integer
     * underflow and overflow, as well as ensure that for indefinite length
     * encodings, there's also enough space for the End-of-Contents (EOC)
     * octets (Tag = 0x00, Length = 0x00, or two bytes).
     */

    /* Determine the maximum length available for this element by finding the
     * first definite length ancestor, if any. */
    sec_asn1d_state* parent = sec_asn1d_get_enclosing_construct(state);
    while (parent && parent->indefinite) {
        parent = sec_asn1d_get_enclosing_construct(parent);
    }
    /* If parent is null, state is either the outermost state / at the top of
     * the stack, or the outermost state uses indefinite length encoding. In
     * these cases, there's nothing external to constrain this element, so
     * there's nothing to check. */
    if (parent) {
        unsigned long remaining = parent->pending;
        parent = state;
        do {
            if (!sec_asn1d_check_and_subtract_length(&remaining, parent->consumed, state->top) ||
                /* If parent->indefinite is true, parent->contents_length is
                 * zero and this is a no-op. */
                !sec_asn1d_check_and_subtract_length(
                    &remaining, parent->contents_length, state->top) ||
                /* If parent->indefinite is true, then ensure there is enough
                 * space for an EOC tag of 2 bytes. */
                (parent->indefinite &&
                 !sec_asn1d_check_and_subtract_length(&remaining, 2, state->top))) {
                /* This element is larger than its enclosing element, which is
                 * invalid. */
                return;
            }
        } while ((parent = sec_asn1d_get_enclosing_construct(parent)) && parent->indefinite);
    }

    /*
     * XXX I cannot decide if this allocation should exclude the case
     *     where state->endofcontents is true -- figure it out!
     */
    if (state->allocate) {
        void* dest;

        PORT_Assert(state->dest == NULL);
        /*
		* We are handling a POINTER or a member of a GROUP, and need to
		* allocate for the data structure.
		*/
        dest = sec_asn1d_zalloc(state->top->their_pool, state->theTemplate->size);
        if (dest == NULL) {
            dprintf("decodeError: sec_asn1d_prepare_for_contents zalloc\n");
            state->top->status = decodeError;
            return;
        }
        /* FIXME _ we're losing the dest pointer after this! */
        state->dest = (char*)dest + state->theTemplate->offset;

        /*
		* For a member of a GROUP, our parent will later put the
		* pointer wherever it belongs.  But for a POINTER, we need
		* to record the destination now, in case notify or filter
		* procs need access to it -- they cannot find it otherwise,
		* until it is too late (for one-pass processing).
		*/
        if (state->parent->place == afterPointer) {
            void** placep;

            placep = state->parent->dest;
            *placep = dest;
        }
    }

    /*
     * Remember, length may be indefinite here!  In that case,
     * both contents_length and pending will be zero.
     */
    state->pending = state->contents_length;

    /*
     * An EXPLICIT is nothing but an outer header, which we have
     * already parsed and accepted.  Now we need to do the inner
     * header and its contents.
     */
    if (state->explicit) {
        state->place = afterExplicit;
        state = sec_asn1d_push_state(
            state->top,
            SEC_ASN1GetSubtemplate(state->theTemplate, state->dest, PR_FALSE, buf /* __APPLE__ */, len /* __APPLE__ */),
            state->dest,
            PR_TRUE);
        if (state != NULL) {
            state = sec_asn1d_init_state_based_on_template(state, buf /* __APPLE__ */, len /* __APPLE__ */);
        }
        (void)state;
        return;
    }

    /*
     * For GROUP (SET OF, SEQUENCE OF), even if we know the length here
     * we cannot tell how many items we will end up with ... so push a
     * state that can keep track of "children" (the individual members
     * of the group; we will allocate as we go and put them all together
     * at the end.
     */
    if (state->underlying_kind & SEC_ASN1_GROUP) {
        /* XXX If this assertion holds (should be able to confirm it via
	 * inspection, too) then move this code into the switch statement
	 * below under cases SET_OF and SEQUENCE_OF; it will be cleaner.
	 */
        PORT_Assert(state->underlying_kind == SEC_ASN1_SET_OF ||
                    state->underlying_kind == SEC_ASN1_SEQUENCE_OF ||
                    state->underlying_kind == (SEC_ASN1_SEQUENCE_OF | SEC_ASN1_DYNAMIC) ||
                    state->underlying_kind == (SEC_ASN1_SET_OF | SEC_ASN1_DYNAMIC));
        if (state->contents_length != 0 || state->indefinite) {
            const SecAsn1Template* subt;

            state->place = duringGroup;
            subt = SEC_ASN1GetSubtemplate(
                state->theTemplate, state->dest, PR_FALSE, buf /* __APPLE__ */, len /* __APPLE__ */);
            state = sec_asn1d_push_state(state->top, subt, NULL, PR_TRUE);
            if (state != NULL) {
                if (!state->top->filter_only)
                    state->allocate = PR_TRUE; /* XXX propogate this? */
                /*
			* Do the "before" field notification for next in group.
			*/
                sec_asn1d_notify_before(state->top, state->dest, state->depth);
                state = sec_asn1d_init_state_based_on_template(
                    state, buf /* __APPLE__ */, len /* __APPLE__ */);
            }
        } else {
            /*
	     * A group of zero; we are done.
	     * Set state to afterGroup and let that code plant the NULL.
	     */
            state->place = afterGroup;
        }
        (void)state;
        return;
    }

    switch (state->underlying_kind) {
        case SEC_ASN1_SEQUENCE:
            /*
	 * We need to push a child to handle the individual fields.
	 */
            state->place = duringSequence;
            state = sec_asn1d_push_state(state->top, state->theTemplate + 1, state->dest, PR_TRUE);
            if (state != NULL) {
                /*
	     * Do the "before" field notification.
	     */
                sec_asn1d_notify_before(state->top, state->dest, state->depth);
                state = sec_asn1d_init_state_based_on_template(
                    state, buf /* __APPLE__ */, len /* __APPLE__ */);
            }
            (void)state;
            break;

        case SEC_ASN1_SET: /* XXX SET is not really implemented */
            /*
	 * XXX A plain SET requires special handling; scanning of a
	 * template to see where a field should go (because by definition,
	 * they are not in any particular order, and you have to look at
	 * each tag to disambiguate what the field is).  We may never
	 * implement this because in practice, it seems to be unused.
	 */
            dprintf("decodeError: prepare for contents SEC_ASN1_SET\n");
            PORT_Assert(0);
            PORT_SetError(SEC_ERROR_BAD_DER); /* XXX */
            state->top->status = decodeError;
            break;

        case SEC_ASN1_NULL:
            /*
	 * The NULL type, by definition, is "nothing", content length of zero.
	 * An indefinite-length encoding is not alloweed.
	 */
            if (state->contents_length || state->indefinite) {
                dprintf("decodeError: prepare for contents indefinite NULL\n");
                PORT_SetError(SEC_ERROR_BAD_DER);
                state->top->status = decodeError;
                break;
            }
            if (state->dest != NULL) {
                item = (SecAsn1Item*)(state->dest);
                item->Data = NULL;
                item->Length = 0;
            }
            state->place = afterEndOfContents;
            break;

        case SEC_ASN1_BMP_STRING:
            /* Error if length is not divisable by 2 */
            if (state->contents_length % 2) {
                dprintf("decodeError: prepare for contents odd length BMP_STRING\n");
                PORT_SetError(SEC_ERROR_BAD_DER);
                state->top->status = decodeError;
                break;
            }
            /* otherwise, handle as other string types */
            goto regular_string_type;

        case SEC_ASN1_UNIVERSAL_STRING:
            /* Error if length is not divisable by 4 */
            if (state->contents_length % 4) {
                dprintf("decodeError: prepare for contents odd length UNIV_STRING\n");
                PORT_SetError(SEC_ERROR_BAD_DER);
                state->top->status = decodeError;
                break;
            }
            /* otherwise, handle as other string types */
            goto regular_string_type;

        case SEC_ASN1_SKIP:
        case SEC_ASN1_ANY:
        case SEC_ASN1_ANY_CONTENTS:
            /*
	 * These are not (necessarily) strings, but they need nearly
	 * identical handling (especially when we need to deal with
	 * constructed sub-pieces), so we pretend they are.
	 */
            /* fallthru */
        regular_string_type:
        case SEC_ASN1_BIT_STRING:
        case SEC_ASN1_IA5_STRING:
        case SEC_ASN1_OCTET_STRING:
        case SEC_ASN1_PRINTABLE_STRING:
        case SEC_ASN1_T61_STRING:
        case SEC_ASN1_UTC_TIME:
        case SEC_ASN1_UTF8_STRING:
        case SEC_ASN1_VISIBLE_STRING:
            /*
	 * We are allocating for a primitive or a constructed string.
	 * If it is a constructed string, it may also be indefinite-length.
	 * If it is primitive, the length can (legally) be zero.
	 * Our first order of business is to allocate the memory for
	 * the string, if we can (if we know the length).
	 */
            item = (SecAsn1Item*)(state->dest);

            /*
	 * If the item is a definite-length constructed string, then
	 * the contents_length is actually larger than what we need
	 * (because it also counts each intermediate header which we
	 * will be throwing away as we go), but it is a perfectly good
	 * upper bound that we just allocate anyway, and then concat
	 * as we go; we end up wasting a few extra bytes but save a
	 * whole other copy.
	 */
            alloc_len = state->contents_length;
            poolp = NULL; /* quiet compiler warnings about unused... */

            if (item == NULL || state->top->filter_only) {
                if (item != NULL) {
                    item->Data = NULL;
                    item->Length = 0;
                }
                alloc_len = 0;
            } else if (state->substring) {
                /*
	     * If we are a substring of a constructed string, then we may
	     * not have to allocate anything (because our parent, the
	     * actual constructed string, did it for us).  If we are a
	     * substring and we *do* have to allocate, that means our
	     * parent is an indefinite-length, so we allocate from our pool;
	     * later our parent will copy our string into the aggregated
	     * whole and free our pool allocation.
	     */
                if (item->Data == NULL) {
                    PORT_Assert(item->Length == 0);
                    poolp = state->top->our_pool;
                } else {
                    alloc_len = 0;
                }
            } else {
                item->Length = 0;
                item->Data = NULL;
                poolp = state->top->their_pool;
            }

            if (alloc_len || ((!state->indefinite) && (state->subitems_head != NULL))) {
                struct subitem* subitem;

                PORT_Assert(item != NULL);
                if (item == NULL) {
                    PORT_SetError(SEC_ERROR_BAD_DER);
                    state->top->status = decodeError;
                    return;
                }
                PORT_Assert(item->Length == 0 && item->Data == NULL);
                /*
	     * Check for and handle an ANY which has stashed aside the
	     * header (identifier and length) bytes for us to include
	     * in the saved contents.
	     */
                if (state->subitems_head != NULL) {
                    PORT_Assert(state->underlying_kind == SEC_ASN1_ANY);
                    for (subitem = state->subitems_head; subitem != NULL;
                         subitem = subitem->next) {
                        alloc_len += subitem->len;
                    }
                }

                if (item) {
                    item->Data = (unsigned char*)sec_asn1d_zalloc(poolp, alloc_len);
                }
                if (item == NULL || item->Data == NULL) {
                    dprintf("decodeError: prepare for contents zalloc\n");
                    state->top->status = decodeError;
                    break;
                }

                unsigned long item_len = 0;
                for (subitem = state->subitems_head; subitem != NULL; subitem = subitem->next) {
                    PORT_Memcpy(item->Data + item_len, subitem->data, subitem->len);
                    item_len += subitem->len;
                }
                item->Length = item_len;

                /*
	     * Because we use arenas and have a mark set, we later free
	     * everything we have allocated, so this does *not* present
	     * a memory leak (it is just temporarily left dangling).
	     */
                state->subitems_head = state->subitems_tail = NULL;
            }

            if (state->contents_length == 0 && (!state->indefinite)) {
                /*
	     * A zero-length simple or constructed string; we are done.
	     */
                state->place = afterEndOfContents;
            } else if (state->found_tag_modifiers & SEC_ASN1_CONSTRUCTED) {
                const SecAsn1Template* sub;

                switch (state->underlying_kind) {
                    case SEC_ASN1_ANY:
                    case SEC_ASN1_ANY_CONTENTS:
                        sub = kSecAsn1AnyTemplate;
                        break;
                    case SEC_ASN1_BIT_STRING:
                        sub = kSecAsn1BitStringTemplate;
                        break;
                    case SEC_ASN1_BMP_STRING:
                        sub = kSecAsn1BMPStringTemplate;
                        break;
                    case SEC_ASN1_GENERALIZED_TIME:
                        sub = kSecAsn1GeneralizedTimeTemplate;
                        break;
                    case SEC_ASN1_IA5_STRING:
                        sub = kSecAsn1IA5StringTemplate;
                        break;
                    case SEC_ASN1_OCTET_STRING:
                        sub = kSecAsn1OctetStringTemplate;
                        break;
                    case SEC_ASN1_PRINTABLE_STRING:
                        sub = kSecAsn1PrintableStringTemplate;
                        break;
                    case SEC_ASN1_T61_STRING:
                        sub = kSecAsn1T61StringTemplate;
                        break;
                    case SEC_ASN1_UNIVERSAL_STRING:
                        sub = kSecAsn1UniversalStringTemplate;
                        break;
                    case SEC_ASN1_UTC_TIME:
                        sub = kSecAsn1UTCTimeTemplate;
                        break;
                    case SEC_ASN1_UTF8_STRING:
                        sub = kSecAsn1UTF8StringTemplate;
                        break;
                    case SEC_ASN1_VISIBLE_STRING:
                        sub = kSecAsn1VisibleStringTemplate;
                        break;
                    case SEC_ASN1_SKIP:
                        sub = kSecAsn1SkipTemplate;
                        break;
                    default:            /* redundant given outer switch cases, but */
                        PORT_Assert(0); /* the compiler does not seem to know that, */
                        sub = NULL;     /* so just do enough to quiet it. */
                        break;
                }

                state->place = duringConstructedString;
                state = sec_asn1d_push_state(state->top, sub, item, PR_TRUE);
                if (state != NULL) {
                    state->substring = PR_TRUE; /* XXX propogate? */
                    state = sec_asn1d_init_state_based_on_template(
                        state, buf /* __APPLE__ */, len /* __APPLE__ */);
                }
            } else if (state->indefinite) {
                /*
	     * An indefinite-length string *must* be constructed!
	     */
                dprintf("decodeError: prepare for contents indefinite not construncted\n");
                PORT_SetError(SEC_ERROR_BAD_DER);
                state->top->status = decodeError;
            } else {
                /*
	     * A non-zero-length simple string.
	     */
                if (state->underlying_kind == SEC_ASN1_BIT_STRING) {
                    state->place = beforeBitString;
                } else {
                    state->place = duringLeaf;
                }
            }
            (void)state;
            break;

        default:
            /*
	 * We are allocating for a simple leaf item.
	 */
            if (state->contents_length) {
                if (state->dest != NULL) {
                    item = (SecAsn1Item*)(state->dest);
                    item->Length = 0;
                    if (state->top->filter_only) {
                        item->Data = NULL;
                    } else {
                        item->Data = (unsigned char*)sec_asn1d_zalloc(
                            state->top->their_pool, state->contents_length);
                        if (item->Data == NULL) {
                            dprintf("decodeError: prepare for contents zalloc\n");
                            state->top->status = decodeError;
                            return;
                        }
                    }
                }
                state->place = duringLeaf;
            } else {
                /*
	     * An indefinite-length or zero-length item is not allowed.
	     * (All legal cases of such were handled above.)
	     */
                dprintf("decodeError: prepare for contents indefinite zero len \n");
                PORT_SetError(SEC_ERROR_BAD_DER);
                state->top->status = decodeError;
            }
    }
}


static void sec_asn1d_free_child(sec_asn1d_state* state, PRBool error)
{
    if (state->child != NULL) {
        PORT_Assert(error || state->child->consumed == 0);
        PORT_Assert(state->our_mark != NULL);
        PORT_ArenaRelease(state->top->our_pool, state->our_mark);
        if (error && state->top->their_pool == NULL) {
            /*
	     * XXX We need to free anything allocated.
             * At this point, we failed in the middle of decoding. But we
             * can't free the data we previously allocated with PR_Malloc
             * unless we keep track of every pointer. So instead we have a
             * memory leak when decoding fails half-way, unless an arena is
             * used. See bug 95311 .
	     */
        }
        state->child = NULL;
        state->our_mark = NULL;
    } else {
        /*
	 * It is important that we do not leave a mark unreleased/unmarked.
	 * But I do not think we should ever have one set in this case, only
	 * if we had a child (handled above).  So check for that.  If this
	 * assertion should ever get hit, then we probably need to add code
	 * here to release back to our_mark (and then set our_mark to NULL).
	 */
        PORT_Assert(state->our_mark == NULL);
    }
    state->place = beforeEndOfContents;
}


/* We have just saved an entire encoded ASN.1 object (type) for a SAVE 
** template, and now in the next template, we are going to decode that 
** saved data  by calling SEC_ASN1DecoderUpdate recursively.
** If that recursive call fails with needBytes, it is a fatal error,
** because the encoded object should have been complete.
** If that recursive call fails with decodeError, it will have already
** cleaned up the state stack, so we must bail out quickly.
**
** These checks of the status returned by the recursive call are now
** done in the caller of this function, immediately after it returns.
*/
static void sec_asn1d_reuse_encoding(sec_asn1d_state* state)
{
    sec_asn1d_state* child;
    unsigned long consumed;
    SecAsn1Item* item;
    void* dest;


    child = state->child;
    PORT_Assert(child != NULL);

    consumed = child->consumed;
    child->consumed = 0;

    item = (SecAsn1Item*)(state->dest);
    PORT_Assert(item != NULL);

    PORT_Assert(item->Length == consumed);

    /*
     * Free any grandchild.
     */
    sec_asn1d_free_child(child, PR_FALSE);

    /*
     * Notify after the SAVE field.
     */
    sec_asn1d_notify_after(state->top, state->dest, state->depth);

    /*
     * Adjust to get new dest and move forward.
     */
    dest = (char*)state->dest - state->theTemplate->offset;
    state->theTemplate++;
    child->dest = (char*)dest + state->theTemplate->offset;
    child->theTemplate = state->theTemplate;

    /*
     * Notify before the "real" field.
     */
    PORT_Assert(state->depth == child->depth);
    sec_asn1d_notify_before(state->top, child->dest, child->depth);

    /*
     * This will tell DecoderUpdate to return when it is done.
     */
    state->place = afterSaveEncoding;

    /*
     * We already have a child; "push" it by making it current.
     */
    state->top->current = child;

    /*
     * And initialize it so it is ready to parse.
     */
    (void)sec_asn1d_init_state_based_on_template(
        child, (char*)item->Data /* __APPLE__ */, item->Length /* __APPLE__ */);

    /*
     * Now parse that out of our data.
     */
    if (SEC_ASN1DecoderUpdate(state->top, (char*)item->Data, item->Length) != SECSuccess)
        return;
    if (state->top->status == needBytes) {
        return;
    }

    PORT_Assert(state->top->current == state);
    PORT_Assert(state->child == child);

    /*
     * That should have consumed what we consumed before.
     */
    PORT_Assert(consumed == child->consumed);
    child->consumed = 0;

    /*
     * Done.
     */
    state->consumed += consumed;
    child->place = notInUse;
    state->place = afterEndOfContents;
}


static unsigned long sec_asn1d_parse_leaf(sec_asn1d_state* state, const char* buf, unsigned long len)
{
    SecAsn1Item* item;
    unsigned long bufLen;

    if (len == 0) {
        state->top->status = needBytes;
        return 0;
    }

    if (state->pending < len) {
        len = state->pending;
    }

    bufLen = len;

    item = (SecAsn1Item*)(state->dest);
    if (item != NULL && item->Data != NULL) {
        /* Strip leading zeroes when target is unsigned integer */
        if (state->underlying_kind == SEC_ASN1_INTEGER && /* INTEGER   */
            item->Length == 0 &&                          /* MSB       */
#ifdef __APPLE__
            !(state->underlying_kind & SEC_ASN1_SIGNED_INT))
#else
            item->type == siUnsignedInteger) /* unsigned  */
#endif
        {
            while (len > 1 && buf[0] == 0) { /* leading 0 */
                buf++;
                len--;
            }
        }
        unsigned long offset = item->Length;
        if (state->underlying_kind == SEC_ASN1_BIT_STRING) {
            // The previous bit string must have no unused bits.
            if (item->Length & 0x7) {
                PORT_SetError(SEC_ERROR_BAD_DER);
                state->top->status = decodeError;
                return 0;
            }
            // If this is a bit string, the length is bits, not bytes.
            offset = item->Length >> 3;
        }
        if (state->underlying_kind == SEC_ASN1_BIT_STRING) {
            // Protect against overflow during the bytes-to-bits conversion.
            if (len >= (ULONG_MAX >> 3) + 1) {
                PORT_SetError(SEC_ERROR_BAD_DER);
                state->top->status = decodeError;
                return 0;
            }
            unsigned long len_in_bits = (len << 3) - state->bit_string_unused_bits;
            // Protect against overflow when computing the total length in bits.
            if (UINT_MAX - item->Length < len_in_bits) {
                PORT_SetError(SEC_ERROR_BAD_DER);
                state->top->status = decodeError;
                return 0;
            }
            item->Length += len_in_bits;
        } else {
            if (UINT_MAX - item->Length < len) {
                PORT_SetError(SEC_ERROR_BAD_DER);
                state->top->status = decodeError;
                return 0;
            }
            item->Length += len;
        }
        PORT_Memcpy(item->Data + offset, buf, len);
    }
    state->pending -= bufLen;
    if (state->pending == 0) {
        state->place = beforeEndOfContents;
    }

    return bufLen;
}


static unsigned long sec_asn1d_parse_bit_string(sec_asn1d_state* state, const char* buf, unsigned long len)
{
    unsigned char byte;

    /*PORT_Assert (state->pending > 0); */
    PORT_Assert(state->place == beforeBitString);

    if (state->pending == 0) {
        if (state->dest != NULL) {
            SecAsn1Item* item = (SecAsn1Item*)(state->dest);
            item->Data = NULL;
            item->Length = 0;
            state->place = beforeEndOfContents;
            return 0;
        }
    }

    if (len == 0) {
        state->top->status = needBytes;
        return 0;
    }

    byte = (unsigned char)*buf;
    if (byte > 7) {
        dprintf("decodeError: parse_bit_string remainder oflow\n");
        PORT_SetError(SEC_ERROR_BAD_DER);
        state->top->status = decodeError;
        return 0;
    }

    state->bit_string_unused_bits = byte;
    state->place = duringBitString;
    state->pending -= 1;

    return 1;
}


static unsigned long
sec_asn1d_parse_more_bit_string(sec_asn1d_state* state, const char* buf, unsigned long len)
{
    PORT_Assert(state->place == duringBitString);
    if (state->pending == 0) {
        /* An empty bit string with some unused bits is invalid. */
        if (state->bit_string_unused_bits) {
            PORT_SetError(SEC_ERROR_BAD_DER);
            state->top->status = decodeError;
        } else {
            /* An empty bit string with no unused bits is OK. */
            state->place = beforeEndOfContents;
        }
        return 0;
    }

    len = sec_asn1d_parse_leaf(state, buf, len);

    return len;
}


/*
 * XXX All callers should be looking at return value to detect
 * out-of-memory errors (and stop!).
 */
static struct subitem*
sec_asn1d_add_to_subitems(sec_asn1d_state* state, const void* data, unsigned long len, PRBool copy_data)
{
    struct subitem* thing;

    thing = (struct subitem*)sec_asn1d_zalloc(state->top->our_pool, sizeof(struct subitem));
    if (thing == NULL) {
        dprintf("decodeError: zalloc\n");
        state->top->status = decodeError;
        return NULL;
    }

    if (copy_data) {
        void* copy;
        copy = sec_asn1d_alloc(state->top->our_pool, len);
        if (copy == NULL) {
            dprintf("decodeError: alloc\n");
            state->top->status = decodeError;
            if (!state->top->our_pool) {
                PORT_Free(thing);
            }
            return NULL;
        }
        PORT_Memcpy(copy, data, len);
        thing->data = copy;
    } else {
        thing->data = data;
    }
    thing->len = len;
    thing->next = NULL;

    if (state->subitems_head == NULL) {
        PORT_Assert(state->subitems_tail == NULL);
        state->subitems_head = state->subitems_tail = thing;
    } else {
        state->subitems_tail->next = thing;
        state->subitems_tail = thing;
    }

    return thing;
}


static void sec_asn1d_record_any_header(sec_asn1d_state* state, const char* buf, unsigned long len)
{
    SecAsn1Item* item;

    item = (SecAsn1Item*)(state->dest);
    if (item != NULL && item->Data != NULL) {
        dprintf("decodeError: sec_asn1d_record_any_header unknown allocation size\n");
        PORT_SetError (SEC_ERROR_LIBRARY_FAILURE);
        state->top->status = decodeError;
    } else {
        sec_asn1d_add_to_subitems(state, buf, len, PR_TRUE);
    }
}


/*
 * We are moving along through the substrings of a constructed string,
 * and have just finished parsing one -- we need to save our child data
 * (if the child was not already writing directly into the destination)
 * and then move forward by one.
 *
 * We also have to detect when we are done:
 *	- a definite-length encoding stops when our pending value hits 0
 *	- an indefinite-length encoding stops when our child is empty
 *	  (which means it was the end-of-contents octets)
 */
static void sec_asn1d_next_substring(sec_asn1d_state* state)
{
    sec_asn1d_state* child;
    SecAsn1Item* item;
    unsigned long child_consumed;
    PRBool done;

    PORT_Assert(state->place == duringConstructedString);
    PORT_Assert(state->child != NULL);

    child = state->child;

    child_consumed = child->consumed;
    child->consumed = 0;
    state->consumed += child_consumed;

    done = PR_FALSE;

    if (state->pending) {
        PORT_Assert(!state->indefinite);
        if (child_consumed > state->pending) {
            dprintf("decodeError: next_substring consumed > pend\n");
            PORT_SetError(SEC_ERROR_BAD_DER);
            state->top->status = decodeError;
            return;
        }

        state->pending -= child_consumed;
        if (state->pending == 0)
            done = PR_TRUE;
    } else {
        PORT_Assert(state->indefinite);

        item = (SecAsn1Item*)(child->dest);
        /*
     * Iterate over ancestors to determine if any have definite length. If so,
     * space has already been allocated for the substrings and we don't need to
     * save them for concatenation.
     */
        PRBool copying_in_place = PR_FALSE;
        sec_asn1d_state* temp_state = state;
        while (temp_state && item == temp_state->dest && temp_state->indefinite) {
            sec_asn1d_state* parent = sec_asn1d_get_enclosing_construct(temp_state);
            if (!parent || parent->underlying_kind != temp_state->underlying_kind) {
                break;
            }
            if (!parent->indefinite) {
                copying_in_place = PR_TRUE;
                break;
            }
            temp_state = parent;
        }
        if (item != NULL && item->Data != NULL && !copying_in_place) {
            /*
	     * Save the string away for later concatenation.
	     */
            PORT_Assert(item->Data != NULL);
            sec_asn1d_add_to_subitems(state, item->Data, item->Length, PR_FALSE);
            /*
	     * Clear the child item for the next round.
	     */
            item->Data = NULL;
            item->Length = 0;
        }

        /*
	 * If our child was just our end-of-contents octets, we are done.
	 */
        if (child->endofcontents)
            done = PR_TRUE;
    }

    /*
     * Stop or do the next one.
     */
    if (done) {
        child->place = notInUse;
        state->place = afterConstructedString;
    } else {
        sec_asn1d_scrub_state(child);
        state->top->current = child;
    }
}


/*
 * We are doing a SET OF or SEQUENCE OF, and have just finished an item.
 */
static void sec_asn1d_next_in_group(sec_asn1d_state* state,
                                    const char* buf, /* __APPLE__ */
                                    size_t len /* __APPLE__ */)
{
    sec_asn1d_state* child;
    unsigned long child_consumed;

    PORT_Assert(state->place == duringGroup);
    PORT_Assert(state->child != NULL);

    child = state->child;

    child_consumed = child->consumed;
    child->consumed = 0;
    state->consumed += child_consumed;

    /*
     * If our child was just our end-of-contents octets, we are done.
     */
#ifdef __APPLE__
    /* 
	 * Without the check for !child->indefinite, this path could
	 * be taken erroneously if the child is indefinite!
	 */
    if (child->endofcontents && !child->indefinite) {
#else
    if (child->endofcontents) {
#endif /* __APPLE__ */
        /* XXX I removed the PORT_Assert (child->dest == NULL) because there
	 * was a bug in that a template that was a sequence of which also had
	 * a child of a sequence of, in an indefinite group was not working 
	 * properly.  This fix seems to work, (added the if statement below),
	 * and nothing appears broken, but I am putting this note here just
	 * in case. */
        /*
	 * XXX No matter how many times I read that comment,
	 * I cannot figure out what case he was fixing.  I believe what he
	 * did was deliberate, so I am loathe to touch it.  I need to
	 * understand how it could ever be that child->dest != NULL but
	 * child->endofcontents is true, and why it is important to check
	 * that state->subitems_head is NULL.  This really needs to be
	 * figured out, as I am not sure if the following code should be
	 * compensating for "offset", as is done a little farther below
	 * in the more normal case.
	 */
        PORT_Assert(state->indefinite);
        PORT_Assert(state->pending == 0);
        if (child->dest && !state->subitems_head) {
            sec_asn1d_add_to_subitems(state, child->dest, 0, PR_FALSE);
            child->dest = NULL;
        }

        child->place = notInUse;
        state->place = afterGroup;
        return;
    }

    /* 
     * Do the "after" field notification for next in group.
     */
    sec_asn1d_notify_after(state->top, child->dest, child->depth);

    /*
     * Save it away (unless we are not storing).
     */
    if (child->dest != NULL) {
        void* dest;

        dest = child->dest;
        dest = (char*)dest - child->theTemplate->offset;
        sec_asn1d_add_to_subitems(state, dest, 0, PR_FALSE);
        child->dest = NULL;
    }

    /*
     * Account for those bytes; see if we are done.
     */
    if (state->pending) {
        PORT_Assert(!state->indefinite);
        if (child_consumed > state->pending) {
            dprintf("decodeError: next_in_group consumed > pend\n");
            PORT_SetError(SEC_ERROR_BAD_DER);
            state->top->status = decodeError;
            return;
        }

        state->pending -= child_consumed;
        if (state->pending == 0) {
            child->place = notInUse;
            state->place = afterGroup;
            return;
        }
    }

    /*
     * Do the "before" field notification for next item in group.
     */
    sec_asn1d_notify_before(state->top, child->dest, child->depth);

    /*
     * Now we do the next one.
     */
    sec_asn1d_scrub_state(child);

    /* Initialize child state from the template */
    sec_asn1d_init_state_based_on_template(child, buf /* __APPLE__ */, len /* __APPLE__ */);

    state->top->current = child;
}


/*
 * We are moving along through a sequence; move forward by one,
 * (detecting end-of-sequence when it happens).
 * XXX The handling of "missing" is ugly.  Fix it.
 */
static void sec_asn1d_next_in_sequence(sec_asn1d_state* state,
                                       const char* buf /* __APPLE__ */,
                                       size_t len /*__APPLE__*/)
{
    sec_asn1d_state* child;
    unsigned long child_consumed;
    PRBool child_missing;

    PORT_Assert(state->place == duringSequence);
    PORT_Assert(state->child != NULL);

    child = state->child;

    /*
     * Do the "after" field notification.
     */
    sec_asn1d_notify_after(state->top, child->dest, child->depth);

    child_missing = (PRBool)child->missing;
    child_consumed = child->consumed;
    child->consumed = 0;

    /*
     * Take care of accounting.
     */
    if (child_missing) {
        PORT_Assert(child->optional);
    } else {
        state->consumed += child_consumed;
        /*
		 * Free any grandchild.
		 */
        sec_asn1d_free_child(child, PR_FALSE);
        if (state->pending) {
            PORT_Assert(!state->indefinite);
            if (child_consumed > state->pending) {
                dprintf("decodeError: next_in_seq consumed > pend\n");
                PORT_SetError(SEC_ERROR_BAD_DER);
                state->top->status = decodeError;
                return;
            }
            state->pending -= child_consumed;
            if (state->pending == 0) {
                child->theTemplate++;
                while (child->theTemplate->kind != 0) {
                    if ((child->theTemplate->kind & SEC_ASN1_OPTIONAL) == 0) {
                        dprintf("decodeError: next_in_seq child not opt\n");
                        PORT_SetError(SEC_ERROR_BAD_DER);
                        state->top->status = decodeError;
                        return;
                    }
                    child->theTemplate++;
                }
                child->place = notInUse;
                state->place = afterEndOfContents;
                return;
            }
        }
    }

    /*
     * Move forward.
     */
    child->theTemplate++;
    if (child->theTemplate->kind == 0) {
        /*
	 * We are done with this sequence.
	 */
        child->place = notInUse;
        if (state->pending) {
            dprintf("decodeError: next_in_seq notInUse still pending\n");
            PORT_SetError(SEC_ERROR_BAD_DER);
            state->top->status = decodeError;
        } else if (child_missing) {
            /*
	     * We got to the end, but have a child that started parsing
	     * and ended up "missing".  The only legitimate reason for
	     * this is that we had one or more optional fields at the
	     * end of our sequence, and we were encoded indefinite-length,
	     * so when we went looking for those optional fields we
	     * found our end-of-contents octets instead.
	     * (Yes, this is ugly; dunno a better way to handle it.)
	     * So, first confirm the situation, and then mark that we
	     * are done.
	     */
            if (state->indefinite && child->endofcontents) {
                PORT_Assert(child_consumed == 2);
                if (child_consumed != 2) {
                    dprintf("decodeError: next_in_seq indef len != 2\n");
                    PORT_SetError(SEC_ERROR_BAD_DER);
                    state->top->status = decodeError;
                } else {
                    state->consumed += child_consumed;
                    state->place = afterEndOfContents;
                }
            } else {
                dprintf("decodeError: next_in_seq !indef, child missing\n");
                PORT_SetError(SEC_ERROR_BAD_DER);
                state->top->status = decodeError;
            }
        } else {
            /*
	     * We have to finish out, maybe reading end-of-contents octets;
	     * let the normal logic do the right thing.
	     */
            state->place = beforeEndOfContents;
        }
    } else {
        unsigned char child_found_tag_modifiers = 0;
        unsigned long child_found_tag_number = 0;

        /*
	 * Reset state and push.
	 */
        if (state->dest != NULL) {
            child->dest = (char*)state->dest + child->theTemplate->offset;
        }

        /*
	 * Do the "before" field notification.
	 */
        sec_asn1d_notify_before(state->top, child->dest, child->depth);

        if (child_missing) { /* if previous child was missing, copy the tag data we already have */
            child_found_tag_modifiers = child->found_tag_modifiers;
            child_found_tag_number = child->found_tag_number;
        }
        state->top->current = child;
        child = sec_asn1d_init_state_based_on_template(child, buf /* __APPLE__ */, len /* __APPLE__ */);
        if (child_missing && child) {
            child->place = afterIdentifier;
            child->found_tag_modifiers = child_found_tag_modifiers;
            child->found_tag_number = child_found_tag_number;
            child->consumed = child_consumed;
            if (child->underlying_kind == SEC_ASN1_ANY && !child->top->filter_only) {
                /*
		 * If the new field is an ANY, and we are storing, then
		 * we need to save the tag out.  We would have done this
		 * already in the normal case, but since we were looking
		 * for an optional field, and we did not find it, we only
		 * now realize we need to save the tag.
		 */
                unsigned char identifier;

                /*
		 * Check that we did not end up with a high tag; for that
		 * we need to re-encode the tag into multiple bytes in order
		 * to store it back to look like what we parsed originally.
		 * In practice this does not happen, but for completeness
		 * sake it should probably be made to work at some point.
		 */
                PORT_Assert(child_found_tag_number < SEC_ASN1_HIGH_TAG_NUMBER);
                identifier = (unsigned char)(child_found_tag_modifiers | child_found_tag_number);
                sec_asn1d_record_any_header(child, (char*)&identifier, 1);
            }
        }
    }
}


static void sec_asn1d_concat_substrings(sec_asn1d_state* state)
{
    PORT_Assert(state->place == afterConstructedString);

    if (state->subitems_head != NULL) {
        struct subitem* substring;
        unsigned long alloc_len, item_len;
        unsigned char* where;
        SecAsn1Item* item;
        PRBool is_bit_string;

        item_len = 0;
        is_bit_string = (state->underlying_kind == SEC_ASN1_BIT_STRING) ? PR_TRUE : PR_FALSE;

        substring = state->subitems_head;
        while (substring != NULL) {
            /*
	     * All bit-string substrings except the last one should be
	     * a clean multiple of 8 bits.
	     */
            if (is_bit_string && (substring->next != NULL) && (substring->len & 0x7)) {
                dprintf("decodeError: sec_asn1d_concat_substrings align\n");
                PORT_SetError(SEC_ERROR_BAD_DER);
                state->top->status = decodeError;
                return;
            }
            item_len += substring->len;
            substring = substring->next;
        }

        if (is_bit_string) {
#ifdef XP_WIN16 /* win16 compiler gets an internal error otherwise */
            alloc_len = (((long)item_len + 7) / 8);
#else
            alloc_len = ((item_len + 7) >> 3);
#endif
        } else {
            /*
	     * Add 2 for the end-of-contents octets of an indefinite-length
	     * ANY that is *not* also an INNER.  Because we zero-allocate
	     * below, all we need to do is increase the length here.
	     */
            if (state->underlying_kind == SEC_ASN1_ANY && state->indefinite)
                item_len += 2;
            alloc_len = item_len;
        }

        item = (SecAsn1Item*)(state->dest);
        PORT_Assert(item != NULL);
        PORT_Assert(item->Data == NULL);
        item->Data = (unsigned char*)sec_asn1d_zalloc(state->top->their_pool, alloc_len);
        if (item->Data == NULL) {
            dprintf("decodeError: zalloc\n");
            state->top->status = decodeError;
            return;
        }
        item->Length = item_len;

        where = item->Data;
        substring = state->subitems_head;
        while (substring != NULL) {
            if (is_bit_string)
                item_len = (substring->len + 7) >> 3;
            else
                item_len = substring->len;
            PORT_Memcpy(where, substring->data, item_len);
            where += item_len;
            substring = substring->next;
        }

        /*
	 * Because we use arenas and have a mark set, we later free
	 * everything we have allocated, so this does *not* present
	 * a memory leak (it is just temporarily left dangling).
	 */
        state->subitems_head = state->subitems_tail = NULL;
    }

    state->place = afterEndOfContents;
}


static void sec_asn1d_concat_group(sec_asn1d_state* state)
{
    const void*** placep;

    PORT_Assert(state->place == afterGroup);

    placep = (const void***)state->dest;
    PORT_Assert(state->subitems_head == NULL || placep != NULL);
    if (placep != NULL) {
        struct subitem* item = state->subitems_head;
        const void** group;
        unsigned long count = 0;

        while (item != NULL) {
            PORT_Assert(item->next != NULL || item == state->subitems_tail);
            count++;
            item = item->next;
        }

        group = (const void**)sec_asn1d_zalloc(state->top->their_pool,
                                               (count + 1) * (sizeof(void*)));
        if (group == NULL) {
            dprintf("decodeError: zalloc\n");
            state->top->status = decodeError;
            return;
        }

        *placep = group;

        item = state->subitems_head;
        while (item != NULL) {
            *group++ = item->data;
            item = item->next;
        }
        *group = NULL;

        /*
	 * Because we use arenas and have a mark set, we later free
	 * everything we have allocated, so this does *not* present
	 * a memory leak (it is just temporarily left dangling).
	 */
        state->subitems_head = state->subitems_tail = NULL;
    }

    state->place = afterEndOfContents;
}

/*
 * For those states that push a child to handle a subtemplate,
 * "absorb" that child (transfer necessary information).
 */
static void sec_asn1d_absorb_child(sec_asn1d_state* state)
{
    /*
     * There is absolutely supposed to be a child there.
     */
    PORT_Assert(state->child != NULL);

    /*
     * Inherit the missing status of our child, and do the ugly
     * backing-up if necessary.
     */
    state->missing = state->child->missing;
    if (state->missing) {
        state->found_tag_number = state->child->found_tag_number;
        state->found_tag_modifiers = state->child->found_tag_modifiers;
        state->endofcontents = state->child->endofcontents;
    }

    /*
     * Add in number of bytes consumed by child.
     * (Only EXPLICIT should have already consumed bytes itself.)
     */
    PORT_Assert(state->place == afterExplicit || state->consumed == 0);
    state->consumed += state->child->consumed;

    /*
     * Subtract from bytes pending; this only applies to a definite-length
     * EXPLICIT field.
     */
    if (state->pending) {
        PORT_Assert(!state->indefinite);
        PORT_Assert(state->place == afterExplicit);

        /*
	 * If we had a definite-length explicit, then what the child
	 * consumed should be what was left pending.
	 */
        if (state->pending != state->child->consumed) {
            dprintf("decodeError: absorb_child pending != consumed\n");
            PORT_SetError(SEC_ERROR_BAD_DER);
            state->top->status = decodeError;
            return;
        }
        state->pending = 0;
    }

    /*
     * Indicate that we are done with child.
     */
    state->child->consumed = 0;

    /*
     * And move on to final state.
     * (Technically everybody could move to afterEndOfContents except
     * for an indefinite-length EXPLICIT; for simplicity though we assert
     * that but let the end-of-contents code do the real determination.)
     */
    PORT_Assert(state->place == afterExplicit || (!state->indefinite));
    state->place = beforeEndOfContents;
}


static void sec_asn1d_prepare_for_end_of_contents(sec_asn1d_state* state)
{
    PORT_Assert(state->place == beforeEndOfContents);

    if (state->indefinite) {
        state->place = duringEndOfContents;
        state->pending = 2;
    } else {
        state->place = afterEndOfContents;
    }
}


static unsigned long
sec_asn1d_parse_end_of_contents(sec_asn1d_state* state, const char* buf, unsigned long len)
{
    unsigned int i;

    PORT_Assert(state->pending <= 2);
    PORT_Assert(state->place == duringEndOfContents);

    if (len == 0) {
        state->top->status = needBytes;
        return 0;
    }

    if (state->pending < len) {
        len = state->pending;
    }

    for (i = 0; i < len; i++) {
        if (buf[i] != 0) {
            /*
	     * We expect to find only zeros; if not, just give up.
	     */
            dprintf("decodeError: end of contents non zero\n");
            PORT_SetError(SEC_ERROR_BAD_DER);
            state->top->status = decodeError;
            return 0;
        }
    }

    state->pending -= len;

    if (state->pending == 0) {
        state->place = afterEndOfContents;
        state->endofcontents = PR_TRUE;
    }

    return len;
}


static void sec_asn1d_pop_state(sec_asn1d_state* state)
{
#if 0  /* XXX I think this should always be handled explicitly by parent? */
    /*
     * Account for our child.
     */
    if (state->child != NULL) {
	state->consumed += state->child->consumed;
	if (state->pending) {
	    PORT_Assert (!state->indefinite);
	    if( state->child->consumed > state->pending ) {
			dprintf("decodeError: pop_state pending < consumed\n");	
			PORT_SetError (SEC_ERROR_BAD_DER);
			state->top->status = decodeError;
	    } else {
			state->pending -= state->child->consumed;
	    }
	}
	state->child->consumed = 0;
    }
#endif /* XXX */

    /*
     * Free our child.
     */
    sec_asn1d_free_child(state, PR_FALSE);

    /*
     * Just make my parent be the current state.  It will then clean
     * up after me and free me (or reuse me).
     */
    state->top->current = state->parent;
}

static sec_asn1d_state* sec_asn1d_before_choice(sec_asn1d_state* state,
                                                const char* buf /* __APPLE__ */,
                                                size_t len /* __APPLE__ */)
{
    sec_asn1d_state* child;

    if (state->allocate) {
        void* dest;

        dest = sec_asn1d_zalloc(state->top->their_pool, state->theTemplate->size);
        if ((void*)NULL == dest) {
            dprintf("decodeError: zalloc\n");
            state->top->status = decodeError;
            return (sec_asn1d_state*)NULL;
        }

        state->dest = (char*)dest + state->theTemplate->offset;
    }

    child = sec_asn1d_push_state(
        state->top, state->theTemplate + 1, (char*)state->dest - state->theTemplate->offset, PR_FALSE);
    if ((sec_asn1d_state*)NULL == child) {
        return (sec_asn1d_state*)NULL;
    }

    sec_asn1d_scrub_state(child);
    child = sec_asn1d_init_state_based_on_template(child, buf /* __APPLE__ */, len /* __APPLE__ */);
    if ((sec_asn1d_state*)NULL == child) {
        return (sec_asn1d_state*)NULL;
    }

    child->optional = PR_TRUE;

    state->place = duringChoice;

    return child;
}

static sec_asn1d_state* sec_asn1d_during_choice(sec_asn1d_state* state,
                                                const char* buf, /* __APPLE__ */
                                                size_t len /* __APPLE__ */)
{
    sec_asn1d_state* child = state->child;

    PORT_Assert((sec_asn1d_state*)NULL != child);

    if (child->missing) {
        unsigned char child_found_tag_modifiers = 0;
        unsigned long child_found_tag_number = 0;
        void* dest;

        state->consumed += child->consumed;

        if (child->endofcontents) {
            /* This choice is probably the first item in a GROUP
        ** (e.g. SET_OF) that was indefinite-length encoded.
        ** We're actually at the end of that GROUP.
        ** We look up the stack to be sure that we find
        ** a state with indefinite length encoding before we
        ** find a state (like a SEQUENCE) that is definite.
        */
            child->place = notInUse;
            state->place = afterChoice;
            state->endofcontents = PR_TRUE; /* propagate this up */
            if (sec_asn1d_parent_allows_EOC(state))
                return state;
            dprintf("decodeError: during_choice child at EOC by parent does not allow EOC\n");
            PORT_SetError(SEC_ERROR_BAD_DER);
            state->top->status = decodeError;
            return NULL;
        }

        dest = (char*)child->dest - child->theTemplate->offset;
        child->theTemplate++;

        if (0 == child->theTemplate->kind) {
            /* Ran out of choices */
            dprintf("decodeError: during_choice ran out of choice\n");
            PORT_SetError(SEC_ERROR_BAD_DER);
            state->top->status = decodeError;
            return (sec_asn1d_state*)NULL;
        }
        child->dest = (char*)dest + child->theTemplate->offset;

        /* cargo'd from next_in_sequence innards */
        if (state->pending) {
            PORT_Assert(!state->indefinite);
            if (child->consumed > state->pending) {
                dprintf("decodeError: during_choice consumed > pending\n");
                PORT_SetError(SEC_ERROR_BAD_DER);
                state->top->status = decodeError;
                return NULL;
            }
            state->pending -= child->consumed;
            if (0 == state->pending) {
                /* XXX uh.. not sure if I should have stopped this
         * from happening before. */
                PORT_Assert(0);
                PORT_SetError(SEC_ERROR_BAD_DER);
                dprintf("decodeError: during_choice !pending\n");
                state->top->status = decodeError;
                return (sec_asn1d_state*)NULL;
            }
        }

        child->consumed = 0;
        sec_asn1d_scrub_state(child);

        /* move it on top again */
        state->top->current = child;

        child_found_tag_modifiers = child->found_tag_modifiers;
        child_found_tag_number = child->found_tag_number;

        child = sec_asn1d_init_state_based_on_template(child, buf /* __APPLE__*/, len /* __APPLE__ */);
        if ((sec_asn1d_state*)NULL == child) {
            return (sec_asn1d_state*)NULL;
        }

        /* copy our findings to the new top */
        child->found_tag_modifiers = child_found_tag_modifiers;
        child->found_tag_number = child_found_tag_number;

        child->optional = PR_TRUE;
        child->place = afterIdentifier;

        return child;
    }
    if ((void*)NULL != state->dest) {
        /* Store the enum */
        int* which = (int*)state->dest;
        *which = (int)child->theTemplate->size;
    }

    child->place = notInUse;

    state->place = afterChoice;
    return state;
}

static void sec_asn1d_after_choice(sec_asn1d_state* state)
{
    state->consumed += state->child->consumed;
    state->child->consumed = 0;
    state->place = afterEndOfContents;
    sec_asn1d_pop_state(state);
}

#if 0
unsigned long
sec_asn1d_uinteger(SecAsn1Item *src)
{
    unsigned long value;
    int len;

    if (src->Length > 5 || (src->Length > 4 && src->Data[0] == 0))
	return 0;

    value = 0;
    len = src->Length;
    while (len) {
	value <<= 8;
	value |= src->Data[--len];
    }
    return value;
}
#endif

SECStatus SEC_ASN1DecodeInteger(SecAsn1Item* src, unsigned long* value)
{
    unsigned long v;
    unsigned int i;

    if (src == NULL) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    if (src->Length > sizeof(unsigned long)) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    if (src->Data == NULL) {
        PORT_SetError(SEC_ERROR_INVALID_ARGS);
        return SECFailure;
    }

    if (src->Data[0] & 0x80) {
        v = ULONG_MAX; /* signed and negative - start with all 1's */
    } else {
        v = 0;
    }

    for (i = 0; i < src->Length; i++) {
        /* shift in next byte */
        v <<= 8;
        v |= src->Data[i];
    }
    *value = v;
    return SECSuccess;
}

#ifdef DEBUG_ASN1D_STATES
static void dump_states(SEC_ASN1DecoderContext* cx)
{
    sec_asn1d_state* state;
    char kindBuf[256];

    for (state = cx->current; state->parent; state = state->parent) {
        ;
    }

    for (; state; state = state->child) {
        int i;
        for (i = 0; i < state->depth; i++) {
            printf("  ");
        }

        i = formatKind(state->theTemplate->kind, kindBuf, sizeof(kindBuf));
        printf("%s: tmpl %p, kind%s", (state == cx->current) ? "STATE" : "State", state->theTemplate, kindBuf);
        printf(" %s", (state->place <= notInUse) ? place_names[state->place] : "(undefined)");
        if (!i) {
            printf(", expect 0x%02lx", state->expect_tag_number | state->expect_tag_modifiers);
        }

        printf("%s%s%s %lu\n",
               state->indefinite ? ", indef" : "",
               state->missing ? ", miss" : "",
               state->endofcontents ? ", EOC" : "",
               state->pending);
    }

    return;
}
#endif /* DEBUG_ASN1D_STATES */

SECStatus SEC_ASN1DecoderUpdate(SEC_ASN1DecoderContext* cx, const char* buf, size_t len)
{
    sec_asn1d_state* state = NULL;
    unsigned long consumed;
    SEC_ASN1EncodingPart what;
    sec_asn1d_state* stateEnd = cx->current;

    if (cx->status == needBytes)
        cx->status = keepGoing;

    while (cx->status == keepGoing) {
        state = cx->current;
        what = SEC_ASN1_Contents;
        consumed = 0;
#if DEBUG_ASN1D_STATES
        if (doDumpStates > 1) {
            printf("\nPLACE = %s, next byte = 0x%02x, %p[%lu]\n",
                   (state->place <= notInUse) ? place_names[state->place] : "(undefined)",
                   (unsigned int)((unsigned char*)buf)[consumed],
                   buf,
                   consumed);
            dump_states(cx);
        }
#endif /* DEBUG_ASN1D_STATES */
        switch (state->place) {
            case beforeIdentifier:
                consumed = sec_asn1d_parse_identifier(state, buf, len);
                what = SEC_ASN1_Identifier;
                break;
            case duringIdentifier:
                consumed = sec_asn1d_parse_more_identifier(state, buf, len);
                what = SEC_ASN1_Identifier;
                break;
            case afterIdentifier:
                sec_asn1d_confirm_identifier(state);
                break;
            case beforeLength:
                consumed = sec_asn1d_parse_length(state, buf, len);
                what = SEC_ASN1_Length;
                break;
            case duringLength:
                consumed = sec_asn1d_parse_more_length(state, buf, len);
                what = SEC_ASN1_Length;
                break;
            case afterLength:
                sec_asn1d_prepare_for_contents(state, buf, len);
                break;
            case beforeBitString:
                consumed = sec_asn1d_parse_bit_string(state, buf, len);
                break;
            case duringBitString:
                consumed = sec_asn1d_parse_more_bit_string(state, buf, len);
                break;
            case duringConstructedString:
                sec_asn1d_next_substring(state);
                break;
            case duringGroup:
                sec_asn1d_next_in_group(state, buf, len);
                break;
            case duringLeaf:
                consumed = sec_asn1d_parse_leaf(state, buf, len);
                break;
            case duringSaveEncoding:
                sec_asn1d_reuse_encoding(state);
                if (cx->status == decodeError) {
                    /* recursive call has already popped all states from stack.
                            ** Bail out quickly.
                            */
                    return SECFailure;
                }
                if (cx->status == needBytes) {
                    /* recursive call wanted more data. Fatal. Clean up below. */
                    PORT_SetError(SEC_ERROR_BAD_DER);
                    cx->status = decodeError;
                }
                break;
            case duringSequence:
                sec_asn1d_next_in_sequence(state, buf, len);
                break;
            case afterConstructedString:
                sec_asn1d_concat_substrings(state);
                break;
            case afterExplicit:
            case afterImplicit:
            case afterInline:
            case afterPointer:
                sec_asn1d_absorb_child(state);
                break;
            case afterGroup:
                sec_asn1d_concat_group(state);
                break;
            case afterSaveEncoding:
                /* SEC_ASN1DecoderUpdate has called itself recursively to 
			** decode SAVEd encoded data, and now is done decoding that.
			** Return to the calling copy of SEC_ASN1DecoderUpdate.
			*/
                return SECSuccess;
            case beforeEndOfContents:
                sec_asn1d_prepare_for_end_of_contents(state);
                break;
            case duringEndOfContents:
                consumed = sec_asn1d_parse_end_of_contents(state, buf, len);
                what = SEC_ASN1_EndOfContents;
                break;
            case afterEndOfContents:
                sec_asn1d_pop_state(state);
                break;
            case beforeChoice:
                state = sec_asn1d_before_choice(state, buf, len);
                break;
            case duringChoice:
                state = sec_asn1d_during_choice(state, buf, len);
                break;
            case afterChoice:
                sec_asn1d_after_choice(state);
                break;
            case notInUse:
            default:
                /* This is not an error, but rather a plain old BUG! */
                PORT_Assert(0);
                PORT_SetError(SEC_ERROR_BAD_DER);
                dprintf("decodeError: decoder update bad state->place\n");
                cx->status = decodeError;
                break;
        }

        if (cx->status == decodeError)
            break;

        /* We should not consume more than we have.  */
        PORT_Assert(consumed <= len);
        if (consumed > len) {
            dprintf("decodeError: decoder update consumed > len\n");
            PORT_SetError(SEC_ERROR_BAD_DER);
            cx->status = decodeError;
            break;
        }

        /* It might have changed, so we have to update our local copy.  */
        state = cx->current;

        /* If it is NULL, we have popped all the way to the top.  */
        if (state == NULL) {
            PORT_Assert(consumed == 0);
#if 0	
		/* XXX I want this here, but it seems that we have situations (like
		 * downloading a pkcs7 cert chain from some issuers) that give us a
		 * length which is greater than the entire encoding.  So, we cannot
		 * have this be an error.
		 */
			if (len > 0) {
				dprintf("decodeError: decoder update nonzero len\n");	
				PORT_SetError (SEC_ERROR_BAD_DER);
				cx->status = decodeError;
			}
			else
#endif
            cx->status = allDone;
            break;
        } else if (state->theTemplate->kind == SEC_ASN1_SKIP_REST) {
            cx->status = allDone;
            break;
        }

        if (consumed == 0)
            continue;

        /*
		 * The following check is specifically looking for an ANY
		 * that is *not* also an INNER, because we need to save aside
		 * all bytes in that case -- the contents parts will get
		 * handled like all other contents, and the end-of-contents
		 * bytes are added by the concat code, but the outer header
		 * bytes need to get saved too, so we do them explicitly here.
		 */
        if (state->underlying_kind == SEC_ASN1_ANY && !cx->filter_only &&
            (what == SEC_ASN1_Identifier || what == SEC_ASN1_Length)) {
            sec_asn1d_record_any_header(state, buf, consumed);
        }

        /*
		 * We had some number of good, accepted bytes.  If the caller
		 * has registered to see them, pass them along.
		 */
        if (state->top->filter_proc != NULL) {
            int depth;

            depth = state->depth;
            if (what == SEC_ASN1_EndOfContents && !state->indefinite) {
                PORT_Assert(state->parent != NULL && state->parent->indefinite);
                depth--;
                PORT_Assert(depth == state->parent->depth);
            }
            (*state->top->filter_proc)(state->top->filter_arg, buf, consumed, depth, what);
        }

        state->consumed += consumed;
        buf += consumed;
        len -= consumed;
    } /* main decode loop */

    if (cx->status == decodeError) {
        while (state != NULL && stateEnd->parent != state) {
            sec_asn1d_free_child(state, PR_TRUE);
            state = state->parent;
        }
#ifdef SEC_ASN1D_FREE_ON_ERROR /*
				 * XXX This does not work because we can
				 * end up leaving behind dangling pointers
				 * to stuff that was allocated.  In order
				 * to make this really work (which would
				 * be a good thing, I think), we need to
				 * keep track of every place/pointer that
				 * was allocated and make sure to NULL it
				 * out before we then free back to the mark.	
				 */
        if (cx->their_pool != NULL) {
            PORT_Assert(cx->their_mark != NULL);
            PORT_ArenaRelease(cx->their_pool, cx->their_mark);
        }
#endif
        return SECFailure;
    }

#if 0	
	/* XXX This is what I want, but cannot have because it seems we
	 * have situations (like when downloading a pkcs7 cert chain from
	 * some issuers) that give us a total length which is greater than
	 * the entire encoding.  So, we have to allow allDone to have a
	 * remaining length greater than zero.  I wanted to catch internal
	 * bugs with this, noticing when we do not have the right length.
	 * Oh well.
	 */
    PORT_Assert (len == 0
		 && (cx->status == needBytes || cx->status == allDone));
#else
    PORT_Assert((len == 0 && cx->status == needBytes) || cx->status == allDone);
#endif
    return SECSuccess;
}


SECStatus SEC_ASN1DecoderFinish(SEC_ASN1DecoderContext* cx)
{
    SECStatus rv;

    if (cx->status == needBytes) {
#ifdef __APPLE__
        /*
		 * Special case: need more bytes, but this field and all
		 * subsequent fields are optional. I'm surprised this case is
		 * not handled in the original NSS code, and this workaround
		 * is a bit of a hack...
		 */
        sec_asn1d_state* state = cx->current;
        assert(state != NULL);
        if (state->place == beforeIdentifier) {
            int allOptional = 1;
            const SecAsn1Template* templ = state->theTemplate;
            while (templ->kind != 0) {
                if (!(templ->kind & SEC_ASN1_OPTIONAL)) {
                    allOptional = 0;
                    break;
                }
                templ++;
            }
            if (allOptional) {
                /* letting this one slide */
                rv = SECSuccess;
            } else {
                PORT_SetError(SEC_ERROR_BAD_DER);
                rv = SECFailure;
            }
        } else {
            PORT_SetError(SEC_ERROR_BAD_DER);
            rv = SECFailure;
        }
#else
        PORT_SetError(SEC_ERROR_BAD_DER);
        rv = SECFailure;
#endif /* __APPLE__ */
    } else {
        rv = SECSuccess;
    }

    /*
     * XXX anything else that needs to be finished?
     */

    PORT_FreeArena(cx->our_pool, PR_FALSE);

    return rv;
}


SEC_ASN1DecoderContext* SEC_ASN1DecoderStart(PRArenaPool* their_pool,
                                             void* dest,
                                             const SecAsn1Template* theTemplate
#ifdef __APPLE__
                                             ,
                                             /* only needed if first element will be SEC_ASN1_DYNAMIC */
                                             const char* buf,
                                             size_t len /* __APPLE__ */
#endif
)
{
    PRArenaPool* our_pool;
    SEC_ASN1DecoderContext* cx;

    our_pool = PORT_NewArena(SEC_ASN1_DEFAULT_ARENA_SIZE);
    if (our_pool == NULL)
        return NULL;

    cx = (SEC_ASN1DecoderContext*)PORT_ArenaZAlloc(our_pool, sizeof(*cx));
    if (cx == NULL) {
        PORT_FreeArena(our_pool, PR_FALSE);
        return NULL;
    }

    cx->our_pool = our_pool;
    if (their_pool != NULL) {
        cx->their_pool = their_pool;
#ifdef SEC_ASN1D_FREE_ON_ERROR
        cx->their_mark = PORT_ArenaMark(their_pool);
#endif
    }

    cx->status = needBytes;

    if (sec_asn1d_push_state(cx, theTemplate, dest, PR_FALSE) == NULL ||
        sec_asn1d_init_state_based_on_template(
            cx->current, buf /* __APPLE__ */, len /* __APPLE__ */) == NULL) {
        /*
	 	 * Trouble initializing (probably due to failed allocations)
		 * requires that we just give up.
		 */
        PORT_FreeArena(our_pool, PR_FALSE);
        return NULL;
    }

    return cx;
}


void SEC_ASN1DecoderSetFilterProc(SEC_ASN1DecoderContext* cx, SEC_ASN1WriteProc fn, void* arg, PRBool only)
{
    /* check that we are "between" fields here */
    PORT_Assert(cx->during_notify);

    cx->filter_proc = fn;
    cx->filter_arg = arg;
    cx->filter_only = only;
}


void SEC_ASN1DecoderClearFilterProc(SEC_ASN1DecoderContext* cx)
{
    /* check that we are "between" fields here */
    PORT_Assert(cx->during_notify);

    cx->filter_proc = NULL;
    cx->filter_arg = NULL;
    cx->filter_only = PR_FALSE;
}


void SEC_ASN1DecoderSetNotifyProc(SEC_ASN1DecoderContext* cx, SEC_ASN1NotifyProc fn, void* arg)
{
    cx->notify_proc = fn;
    cx->notify_arg = arg;
}


void SEC_ASN1DecoderClearNotifyProc(SEC_ASN1DecoderContext* cx)
{
    cx->notify_proc = NULL;
    cx->notify_arg = NULL; /* not necessary; just being clean */
}


void SEC_ASN1DecoderAbort(SEC_ASN1DecoderContext* cx, int error)
{
    PORT_Assert(cx);
    PORT_SetError(error);
    cx->status = decodeError;
}


SECStatus
SEC_ASN1Decode(PRArenaPool* poolp, void* dest, const SecAsn1Template* theTemplate, const char* buf, size_t len)
{
    SEC_ASN1DecoderContext* dcx;
    SECStatus urv, frv;

    dcx = SEC_ASN1DecoderStart(poolp, dest, theTemplate, buf /* __APPLE__ */, len /* __APPLE__ */);
    if (dcx == NULL)
        return SECFailure;

    urv = SEC_ASN1DecoderUpdate(dcx, buf, len);
    frv = SEC_ASN1DecoderFinish(dcx);

    if (urv != SECSuccess)
        return urv;

    return frv;
}


SECStatus SEC_ASN1DecodeItem(PRArenaPool* poolp, void* dest, const SecAsn1Template* theTemplate, const SecAsn1Item* item)
{
    return SEC_ASN1Decode(poolp, dest, theTemplate, (const char*)item->Data, item->Length);
}
