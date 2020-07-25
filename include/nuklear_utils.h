#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <limits.h>
#include <time.h>

#include <GL/glew.h>
#include <GLFW/glfw3.h>

#define NK_INCLUDE_FIXED_TYPES
#define NK_INCLUDE_STANDARD_IO
#define NK_INCLUDE_STANDARD_VARARGS
#define NK_INCLUDE_DEFAULT_ALLOCATOR
#define NK_INCLUDE_VERTEX_BUFFER_OUTPUT
#define NK_INCLUDE_FONT_BAKING
#define NK_INCLUDE_DEFAULT_FONT
#define NK_IMPLEMENTATION
#define NK_GLFW_GL3_IMPLEMENTATION
#define NK_KEYSTATE_BASED_INPUT
#include "nuklear.h"
#define WINDOW_WIDTH 1200
#define WINDOW_HEIGHT 800

#define MAX_VERTEX_BUFFER 512 * 1024
#define MAX_ELEMENT_BUFFER 128 * 1024

#include <util.h>


struct nk_style_combo inactive_combo_style(struct nk_context *ctx)
{
    static struct nk_style_combo style;
    static int init = 0;
    if(!init)
    {
        style = ctx->style.combo;
        style.normal = nk_style_item_color(nk_rgb(40,40,40));
        style.hover = nk_style_item_color(nk_rgb(40,40,40));
        style.active = nk_style_item_color(nk_rgb(40,40,40));
        style.border_color = nk_rgb(60,60,60);
        style.label_normal = nk_rgb(60,60,60);
        style.label_hover = nk_rgb(60,60,60);
        style.label_active = nk_rgb(60,60,60);
        style.button.normal = nk_style_item_color(nk_rgb(40,40,40));
        style.button.hover = nk_style_item_color(nk_rgb(40,40,40));
        style.button.active = nk_style_item_color(nk_rgb(40,40,40));
        style.button.text_normal = nk_rgb(60,60,60);
        style.button.text_hover = nk_rgb(60,60,60);
        style.button.text_active = nk_rgb(60,60,60);
        init = 1;
    }
    return style;
}

struct nk_style_button inactive_button_style(struct nk_context *ctx)
{
    static struct nk_style_button style ;
    static int init = 0;
    if(!init)
    {
        style = ctx->style.button;
        style.normal = nk_style_item_color(nk_rgb(40,40,40));
        style.hover = nk_style_item_color(nk_rgb(40,40,40));
        style.active = nk_style_item_color(nk_rgb(40,40,40));
        style.border_color = nk_rgb(60,60,60);
        style.text_background = nk_rgb(60,60,60);
        style.text_normal = nk_rgb(60,60,60);
        style.text_hover = nk_rgb(60,60,60);
        style.text_active = nk_rgb(60,60,60);
        init = 1;
    }
    return style;
}

struct nk_style_edit inactive_edit_style(struct nk_context *ctx)
{
    static struct nk_style_edit style;
    static int init = 0;
    if(!init)
    {
        style = ctx->style.edit;
        style.normal = nk_style_item_color(nk_rgb(40,40,40));
        style.hover = nk_style_item_color(nk_rgb(40,40,40));
        style.active = nk_style_item_color(nk_rgb(40,40,40));
        style.border_color = nk_rgb(60,60,60);
        style.text_normal = nk_rgb(60,60,60);
        style.text_hover = nk_rgb(60,60,60);
        style.text_active = nk_rgb(60,60,60);
        init = 1;
    }
    return style;
}

NK_API int filter_base64(const struct nk_text_edit *box, nk_rune unicode)
{
    NK_UNUSED(box);
    if ((unicode < '0' || unicode > '9') &&
        (unicode < 'a' || unicode > 'z') &&
        (unicode < 'A' || unicode > 'Z') &&
        unicode != '+' && unicode != '/' && unicode != '=')
        return nk_false;
    else return nk_true;
}
void force_base(char * m, int * l, int (*b)(const struct nk_text_edit*, nk_rune))
{
    for(int i = 0; i < *l; i++)
    {

        if(!b(NULL, m[i]))
        {
            memmove(m + i, m + i + 1, (*l) - i);
            i--;
            (*l)--;
        }
    }
}
static void error_callback(int e, const char *d)
{printf("Error %d: %s\n", e, d);}

static void nk_key_input(struct nk_context * ctx_, int key, int scancode, int actions, int mods)
{
    static struct nk_context * ctx;
    
    if(ctx_ != NULL) {
        ctx = ctx_;
        return;
    }

    int a = (actions == GLFW_PRESS || actions == GLFW_REPEAT);
    switch(key)
    {
        case GLFW_KEY_DELETE: nk_input_key(ctx, NK_KEY_DEL, a); break;
        case GLFW_KEY_ENTER: nk_input_key(ctx, NK_KEY_ENTER, a); break;
        case GLFW_KEY_TAB: nk_input_key(ctx, NK_KEY_TAB, a); break;
        case GLFW_KEY_BACKSPACE: nk_input_key(ctx, NK_KEY_BACKSPACE, a); break;
        case GLFW_KEY_UP: nk_input_key(ctx, NK_KEY_UP, a); break;
        case GLFW_KEY_DOWN: nk_input_key(ctx, NK_KEY_DOWN, a); break;
        case GLFW_KEY_LEFT: nk_input_key(ctx, NK_KEY_LEFT, a); break;
        case GLFW_KEY_RIGHT: nk_input_key(ctx, NK_KEY_RIGHT, a); break;
        case GLFW_KEY_HOME: nk_input_key(ctx, NK_KEY_SCROLL_START, a); nk_input_key(ctx, NK_KEY_TEXT_START, a); break;
        case GLFW_KEY_END: nk_input_key(ctx, NK_KEY_TEXT_END, a); nk_input_key(ctx, NK_KEY_SCROLL_END, a); break;
        case GLFW_KEY_PAGE_DOWN: nk_input_key(ctx, NK_KEY_SCROLL_DOWN, a); break;
        case GLFW_KEY_PAGE_UP: nk_input_key(ctx, NK_KEY_SCROLL_UP, a); break;
        case GLFW_KEY_LEFT_SHIFT: nk_input_key(ctx, NK_KEY_SHIFT, a); break;
        case GLFW_KEY_RIGHT_SHIFT: nk_input_key(ctx, NK_KEY_SHIFT, a); break;
        default: break;
    }
    if (mods == GLFW_MOD_CONTROL) {
        switch(key)
        {
            case GLFW_KEY_A: nk_input_key(ctx, NK_KEY_TEXT_SELECT_ALL, a); break;
            case GLFW_KEY_C: nk_input_key(ctx, NK_KEY_COPY, a); break;
            case GLFW_KEY_V: nk_input_key(ctx, NK_KEY_PASTE, a); break;
            case GLFW_KEY_X: nk_input_key(ctx, NK_KEY_CUT, a); break;
        }
    } else {
        switch(key)
        {
            case GLFW_KEY_A: nk_input_key(ctx, NK_KEY_TEXT_SELECT_ALL, 0); break;
            case GLFW_KEY_C: nk_input_key(ctx, NK_KEY_COPY, 0); break;
            case GLFW_KEY_V: nk_input_key(ctx, NK_KEY_PASTE, 0); break;
            case GLFW_KEY_X: nk_input_key(ctx, NK_KEY_CUT, 0); break;
            default: break;
        }
    }
}
static void nk_char_input(struct nk_context * ctx_, unsigned int key)
{
    static struct nk_context * ctx;

    if(ctx_ != NULL) {
        ctx = ctx_;
        return;
    }
    nk_input_unicode(ctx, key);
}
void key_callback(GLFWwindow* window, int key, int scancode, int action, int mods)
{
    nk_key_input(NULL, key, scancode, action, mods);
}
void character_callback(GLFWwindow* window, unsigned int codepoint)
{
    nk_char_input(NULL, codepoint);
}

#include "nuklear_glfw_gl3.h" //:)

static int setup_gui(struct nk_context **ctx, struct nk_glfw *glfw, GLFWwindow **win, int *width, int *height)
{
    #include <font.h>
    
    glfwSetErrorCallback(error_callback);
    if (!glfwInit()) {
        fprintf(stdout, "[GFLW] failed to init!\n");
        exit(1);
    }
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
#ifdef __APPLE__
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#endif
    glfwWindowHint(GLFW_RESIZABLE, GL_FALSE);
    *win = glfwCreateWindow(WINDOW_WIDTH, WINDOW_HEIGHT, "GUICrypt", NULL, NULL);
    glfwMakeContextCurrent(*win);

    int scale = 4;
    int original = 16;
    int size = scale * original;

    GLFWimage i;
    i.width = size;
    i.height = size;
    i.pixels = calloc(sizeof(char), size*size*4);
    char * pixels = calloc(sizeof(char), original*original*4);
    int i_len = original*original*4;
    from_base(hex_icon, original*original*8, pixels, &i_len, original, 0);

    for(int x = 0; x < original; x++)
    {
        for(int y = 0; y < original; y++)
        {
            char * dest = i.pixels + (x*4*scale) + (y*4*scale*size);
            char * src = pixels + x*4 + y*4*original;
            for(int i = 0; i < scale; i++)
            {
                for(int j = 0; j < scale; j++)
                    memcpy(dest + 4*i + size*4*j, src, 4);
            }
        }
    }
     
    glfwSetWindowIcon(*win, 1, &i);

    glfwGetWindowSize(*win, width, height);
    /* OpenGL */
    glViewport(0, 0, WINDOW_WIDTH, WINDOW_HEIGHT);
    glewExperimental = 1;
    if (glewInit() != GLEW_OK) {
        fprintf(stderr, "Failed to setup GLEW\n");
        exit(1);
    }

    *ctx = nk_glfw3_init(glfw, *win, NK_GLFW3_INSTALL_CALLBACKS);
    struct nk_font_atlas *atlas;
    nk_glfw3_font_stash_begin(glfw, &atlas);
    struct nk_font_config cfg = nk_font_config(20);
    cfg.oversample_v = 4;
    cfg.oversample_h = 4;
    

    int len = 62107;
    char * font = malloc(len);
    
    from_base(b64_font, 82808, font, &len, 64, 0);
    
    struct nk_font *some = nk_font_atlas_add_from_memory(atlas, font, len, 20, &cfg);
    nk_glfw3_font_stash_end(glfw);
    nk_style_set_font(*ctx, &some->handle);

    glfwSetKeyCallback(*win, key_callback);
    glfwSetCharCallback(*win, character_callback);
    nk_key_input(*ctx, 0, 0, 0, 0);
    nk_char_input(*ctx, 0);
    #ifdef INCLUDE_STYLE
    /*set_style(ctx, THEME_WHITE);*/
    /*set_style(ctx, THEME_RED);*/
    /*set_style(ctx, THEME_BLUE);*/
    /*set_style(ctx, THEME_DARK);*/
    #endif
    return 1;
}

void paste(struct nk_context *ctx)
{
    char *text = (char *)glfwGetClipboardString(NULL);
    if (text) 
    {
        int i = nk_strlen(text);
        force_base(text, &i, ctx->text_edit.filter);
        nk_textedit_paste(&(ctx->text_edit), text, i);
    }
}