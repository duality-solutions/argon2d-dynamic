#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include "nan.h"

extern "C" {
    #include "argon2/argon2.h"
    /*
    #include "argon2.h"
    #include "bcrypt.h"
    #include "blake.h"
    #include "c11.h"
    #include "cryptonight.h"
    #include "dcrypt.h"
    #include "fresh.h"
    #include "fugue.h"
    #include "groestl.h"
    #include "hefty1.h"
    #include "jh.h"
    #include "keccak.h"
    #include "lyra2.h"
    #include "lyra2re.h"
    #include "lyra2z.h"
    #include "neoscrypt.h"
    #include "nist5.h"
    #include "quark.h"
    #include "qubit.h"
    #include "s3.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "sha1.h"
    #include "shavite3.h"
    #include "skein.h"
    #include "Sponge.h"
    #include "tribus.h"
    #include "whirlpoolx.h"
    #include "x5.h"
    #include "x11.h"
    #include "x11ghost.h"
    #include "x13.h"
    #include "x14.h"
    #include "x15.h"
    #include "zr5.h"
    #include "yescrypt/yescrypt.h"
    #include "yescrypt/sha256_Y.h"
    */
}

#include "boolberry.h"

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)
#define THROW_ERROR_EXCEPTION_WITH_STATUS_CODE(x, y) NanThrowError(x, y)

using namespace node;
using namespace v8;

static const size_t INPUT_BYTES = 80;  // Lenth of a block header in bytes. Input Length = Salt Length (salt = input)
static const size_t OUTPUT_BYTES = 32; // Length of output needed for a 256-bit hash
static const unsigned int DEFAULT_ARGON2_FLAG = 2; //Same as ARGON2_DEFAULT_FLAGS

void argon2d_call(const void *input, void *output)
{
    argon2_context context;
    context.out = (uint8_t *)output;
    context.outlen = (uint32_t)OUTPUT_BYTES;
    context.pwd = (uint8_t *)input;
    context.pwdlen = (uint32_t)INPUT_BYTES;
    context.salt = (uint8_t *)input; //salt = input
    context.saltlen = (uint32_t)INPUT_BYTES;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = DEFAULT_ARGON2_FLAG; // = ARGON2_DEFAULT_FLAGS
    // main configurable Argon2 hash parameters
    context.m_cost = 500;  // Memory in KiB (512KB)
    context.lanes = 8;     // Degree of Parallelism
    context.threads = 1;   // Threads
    context.t_cost = 2;    // Iterations

    argon2_ctx(&context, Argon2_d);
}

void argon2d_dyn_hash(const unsigned char* input, unsigned char* output)
{
    argon2d_call(input, output);
}

void argon2d(const v8::FunctionCallbackInfo<v8::Value>& args) {
    v8::Isolate* isolate = args.GetIsolate();

    if (args.Length() < 1) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
       return;
    }

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target)) {
       isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate,"Argument should be a buffer object.")));
       return;
    }
    unsigned char* input = (unsigned char*)Buffer::Data(target);
    unsigned char* output = (unsigned char*) malloc(sizeof(unsigned char) * 32);
    argon2d_dyn_hash(input, output);

    v8::Local<v8::Value> returnValue = Nan::CopyBuffer(((char*)output), 32).ToLocalChecked();
    args.GetReturnValue().Set(returnValue);
}

/*
NAN_METHOD(lyra2rev2) {

    if (info.Length() < 2)
        return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    lyra2rev2_hash(input, output);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(lyra2z) {

    if (info.Length() < 2)
        return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    lyra2z_hash(input, output);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(neoscrypt_hash) {

    if (info.Length() < 2)
        return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");
char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    neoscrypt(input, output, 0);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(bcrypt) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    bcrypt_hash(input, output);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(blake) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    blake_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(boolberry) {

    if (info.Length() < 2)
        return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();
    Local<Object> target_spad = Nan::To<Object>(info[1]).ToLocalChecked();
    uint32_t height = 1;

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    if(!Buffer::HasInstance(target_spad))
        return THROW_ERROR_EXCEPTION("Argument 2 should be a buffer object.");

    if(info.Length() >= 3) {
        if(info[2]->IsUint32()) {
            height = info[2]->ToUint32()->Uint32Value(); // TODO: This does not like Nan::To<uint32_t>(), the current way is deprecated
        } else {
            return THROW_ERROR_EXCEPTION("Argument 3 should be an unsigned integer.");
        }
    }

    char * input = Buffer::Data(target);
    char * scratchpad = Buffer::Data(target_spad);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);
    uint64_t spad_len = Buffer::Length(target_spad);

    boolberry_hash(input, input_len, scratchpad, spad_len, output, height);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(quark) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    quark_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(x11) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(scrypt) {

   if (info.Length() < 3)
       return THROW_ERROR_EXCEPTION("You must provide buffer to hash, N value, and R value");

   Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

   if(!Buffer::HasInstance(target))
       return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

   Local<Number> numn = Nan::To<Number>(info[1]).ToLocalChecked();
   unsigned int nValue = numn->Value();
   Local<Number> numr = Nan::To<Number>(info[2]).ToLocalChecked();
   unsigned int rValue = numr->Value();

   char * input = Buffer::Data(target);
   char *output = (char*) malloc(sizeof(char) * 32);

   uint32_t input_len = Buffer::Length(target);

   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

   info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(scryptn) {

   if (info.Length() < 2)
       return THROW_ERROR_EXCEPTION("You must provide buffer to hash and N factor.");

   Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

   if(!Buffer::HasInstance(target))
       return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

   Local<Number> num = Nan::To<Number>(info[1]).ToLocalChecked();
   unsigned int nFactor = num->Value();

   char* input = Buffer::Data(target);
   //char output[32]; // Node tries to free this later on but can't and causes a malloc error
   char *output = (char*) malloc(sizeof(char) * 32);

   uint32_t input_len = Buffer::Length(target);

   //unsigned int N = 1 << (getNfactor(input) + 1);
   unsigned int N = 1 << nFactor;
   scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now

   info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(scryptjane) {

    if (info.Length() < 5)
        return THROW_ERROR_EXCEPTION("You must provide two argument: buffer, timestamp as number, and nChainStarTime as number, nMin, and nMax");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("First should be a buffer object.");

    Local<Number> num = Nan::To<Number>(info[1]).ToLocalChecked();
    int timestamp = num->Value();

    Local<Number> num2 = Nan::To<Number>(info[2]).ToLocalChecked();
    int nChainStartTime = num2->Value();

    Local<Number> num3 = Nan::To<Number>(info[3]).ToLocalChecked();
    int nMin = num3->Value();

    Local<Number> num4 = Nan::To<Number>(info[4]).ToLocalChecked();
    int nMax = num4->Value();

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(keccak) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    unsigned int dSize = Buffer::Length(target);

    keccak_hash(input, output, dSize);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(skein) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char *input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    skein_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(groestl) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char *input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    groestl_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(groestlmyriad) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    groestlmyriad_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(fugue) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    fugue_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(qubit) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    qubit_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(hefty1) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    hefty1_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(shavite3) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    shavite3_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(cryptonight) {

    bool fast = false;

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    if (info.Length() >= 2) {
        if(!info[1]->IsBoolean())
            return THROW_ERROR_EXCEPTION("Argument 2 should be a boolean");
        fast = info[1]->ToBoolean()->BooleanValue();
    }

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    if(fast)
        cryptonight_fast_hash(input, output, input_len);
    else
        cryptonight_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(x13) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    x13_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(nist5) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    nist5_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(sha1) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    sha1_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(x15) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    x15_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}

NAN_METHOD(fresh) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    uint32_t input_len = Buffer::Length(target);

    fresh_hash(input, output, input_len);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());
}


NAN_METHOD(yescrypt) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = Nan::To<Object>(info[0]).ToLocalChecked();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char *output = (char*) malloc(sizeof(char) * 32);

    yescrypt_hash(input, output);

    info.GetReturnValue().Set(Nan::NewBuffer(output, 32).ToLocalChecked());

}
*/

void init(v8::Local<v8::Object> target) {
    NODE_SET_METHOD(target, "argon2d", argon2d);
/*
    NODE_SET_METHOD(target, "boolberry", boolberry);
    NODE_SET_METHOD(target, "cryptonight", cryptonight);
    NODE_SET_METHOD(target, "fresh", fresh);

    NODE_SET_METHOD(target, "neoscrypt", neoscrypt);
    NODE_SET_METHOD(target, "nist5", nist5);
    NODE_SET_METHOD(target, "sha1", sha1);
    NODE_SET_METHOD(target, "shavite3", shavite3);
    NODE_SET_METHOD(target, "x13", x13);
    NODE_SET_METHOD(target, "x15", x15);
    NODE_SET_METHOD(target, "yescrypt", yescrypt);


    NODE_SET_METHOD(target, "hefty1", hefty1);
    NODE_SET_METHOD(target, "qubit", qubit);
    NODE_SET_METHOD(target, "fugue", fugue);
    NODE_SET_METHOD(target, "blake", blake);
    NODE_SET_METHOD(target, "groestl", groestl);
    NODE_SET_METHOD(target, "skein", skein);
    NODE_SET_METHOD(target, "bcrypt", bcrypt);
    NODE_SET_METHOD(target, "groestlmyriad", groestlmyriad);
    NODE_SET_METHOD(target, "keccak", keccak);
    NODE_SET_METHOD(target, "scryptjane", scryptjane);
    NODE_SET_METHOD(target, "scryptn", scryptn);
    NODE_SET_METHOD(target, "scrypt", scrypt);
    NODE_SET_METHOD(target, "x11", x11);
    NODE_SET_METHOD(target, "quark", quark);
    NODE_SET_METHOD(target, "lyra2rev2", lyra2rev2);
    NODE_SET_METHOD(target, "lyra2z", lyra2z);

    Nan::Set(target, Nan::New("lyra2z").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(lyra2z)).ToLocalChecked());
    Nan::Set(target, Nan::New("lyra2rev2").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(lyra2rev2)).ToLocalChecked());
    Nan::Set(target, Nan::New("quark").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(quark)).ToLocalChecked());
    Nan::Set(target, Nan::New("x11").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(x11)).ToLocalChecked());
    Nan::Set(target, Nan::New("scrypt").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(scrypt)).ToLocalChecked());
    Nan::Set(target, Nan::New("scryptn").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(scryptn)).ToLocalChecked());
    Nan::Set(target, Nan::New("scryptjane").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(scryptjane)).ToLocalChecked());
    Nan::Set(target, Nan::New("keccak").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(keccak)).ToLocalChecked());
    Nan::Set(target, Nan::New("bcrypt").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(bcrypt)).ToLocalChecked());
    Nan::Set(target, Nan::New("skein").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(skein)).ToLocalChecked());
    Nan::Set(target, Nan::New("groestl").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(groestl)).ToLocalChecked());
    Nan::Set(target, Nan::New("groestlmyriad").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(groestlmyriad)).ToLocalChecked());
    Nan::Set(target, Nan::New("blake").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(blake)).ToLocalChecked());
    Nan::Set(target, Nan::New("fugue").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(fugue)).ToLocalChecked());
    Nan::Set(target, Nan::New("qubit").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(qubit)).ToLocalChecked());
    Nan::Set(target, Nan::New("hefty1").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(hefty1)).ToLocalChecked());
    Nan::Set(target, Nan::New("shavite3").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(shavite3)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight)).ToLocalChecked());
    Nan::Set(target, Nan::New("x13").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(x13)).ToLocalChecked());
    Nan::Set(target, Nan::New("boolberry").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(boolberry)).ToLocalChecked());
    Nan::Set(target, Nan::New("nist5").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(nist5)).ToLocalChecked());
    Nan::Set(target, Nan::New("sha1").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(sha1)).ToLocalChecked());
    Nan::Set(target, Nan::New("x15").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(x15)).ToLocalChecked());
    Nan::Set(target, Nan::New("fresh").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(fresh)).ToLocalChecked());
    Nan::Set(target, Nan::New("neoscrypt").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(neoscrypt_hash)).ToLocalChecked());
    Nan::Set(target, Nan::New("yescrypt").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(yescrypt)).ToLocalChecked());
*/
}

NODE_MODULE(multihashing, init)
