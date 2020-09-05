#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include "nan.h"

extern "C" {
    #include "argon2/argon2.h"
}

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

void init(v8::Local<v8::Object> target) {
    NODE_SET_METHOD(target, "argon2d", argon2d);
}

NODE_MODULE(multihashing, init)
