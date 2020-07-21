#include <gui.h>
#include <crypt.h>
#include <util.h>
#include <nuklear_utils.h>

#define INITIAL_SIZE 512

enum inputs
{
    INPUT, OUTPUT, KEY, IV,
    CIPHER, MODE, KEY_SIZE,
    ROUNDS, ACTION
};
static const char * labels[] = {
    "Plain Text", "Cipher Text", "Key", "IV",
    "Cipher", "Mode", "Key Size",
    "Rounds", "Action"
};

struct state_window {
    char * title;
    char ** str;
    int show;
};
struct state_combo {
    int idx, old, current, def;
    const char ** options;
    int len;
    int enabled;
};
struct state_string {
    char * display;
    char * old_display;
    unsigned char * data;
    int idx, display_len, data_len, base, old_base, has_ascii, append;
    int max_size;
    int enabled;
    int fixed_len;
};
struct crypt_state
{
    struct state_combo cipher, mode, key_size, round, action;
    struct state_string key, iv, input, output;
    struct state_combo ** combo_list;
    int combo_list_size;
    struct state_string ** string_list;
    int string_list_size;
    struct parameters p;
    int state;
};
static const char * base_strings[] = {
    "Hex",
    "Base 64",
    "Binary",
    "ASCII"
};
static const int bases[] = {
    16, 64, 2, 0
};

static const int (*base_filter[])(const struct nk_text_edit*, nk_rune unicode) = {
    nk_filter_hex,
    filter_base64,
    nk_filter_binary,
    nk_filter_default
};

static void split_output(struct state_string * a, int c)
{
    for(int i = 1; i <= a->display_len/c; i++)
    {
        int off = c*i;
        memmove((a->display + off) + 1, a->display + c*i, (a->display_len - off)+10);
        a->display[off] = '\n';
        a->display_len += 1;
    }
}

static void resize(struct state_string * a)
{
    a->max_size *= 2;
    a->display = realloc(a->display, a->max_size);
    a->old_display = realloc(a->old_display, a->max_size);
    a->data = realloc(a->data, a->max_size);
}

void resize_to(struct state_string * a, int size)
{
    while(size > a->max_size/2)
        resize(a);
}

static void check_resize(struct state_string * a)
{
    resize_to(a, MAX(a->display_len, a->data_len));
}

static void display_changed(struct state_string * a)
{
    check_resize(a);
    memset(a->data, 0, a->max_size);
    int old = a->data_len;
    from_base(a->display, a->display_len, a->data, &(a->data_len), bases[a->base], a->idx != INPUT);
    if(a->fixed_len)
        a->data_len = old;
}
static void data_changed(struct state_string * a)
{
    check_resize(a);
    memset(a->display, 0, a->max_size);
    to_base(a->data, a->data_len, a->display, &(a->display_len), bases[a->base]);
}

static void encrypt(struct crypt_state * s)
{
    s->output.data_len = 0;
    unsigned char * temp = malloc(s->input.max_size);
    unsigned long temp_len = s->input.data_len;
    memcpy(temp, s->input.data, s->input.max_size);
    int err = crypt(1, &temp, &temp_len, s->key.data, s->iv.data, &(s->p));

    if(err) {
        print_error(err);
        free(temp);
        s->state = 1;
        return;
    }
    s->state = 0;

    if(s->output.max_size / 2 < temp_len)
        resize_to(&(s->output), temp_len);
    memcpy(s->output.data, temp, temp_len);
    s->output.data_len = temp_len;
    free(temp);
    append_output(s->output.data, &(s->output.data_len), s->iv.enabled, s->iv.data, s->iv.data_len);
}
static void decrypt(struct crypt_state * s)
{
    s->input.data_len = 0;
    unsigned char * temp = calloc(sizeof(char), s->output.max_size);
    unsigned long temp_len = 0;
    unsigned char * iv = calloc(sizeof(char), s->output.max_size);
    unsigned long iv_len = s->p.block_size;

    if(iv_len > s->output.data_len) {
        s->state = 1;
        free(temp);
        free(iv);
        return;
    }

    parse_output(s->output.data, s->output.data_len, temp, &temp_len, s->iv.enabled, iv, iv_len);

    if((long)temp_len < 0) {
        s->state = 1;
        free(temp);
        free(iv);
        return;
    }

    int err = crypt(0, &temp, &temp_len, s->key.data, iv, &(s->p));

    if(err) {
        print_error(err);
        free(temp);
        free(iv);
        s->state = 1;
        return;
    }
    s->state = 0;

    if((long)temp_len < 0)
        return;

    if(s->input.max_size / 2 < temp_len)
        resize_to(&(s->input), temp_len);

    memcpy(s->input.data, temp, temp_len);
    s->input.data_len = temp_len;

    memcpy(s->iv.data, iv, iv_len);

    free(temp);
    free(iv);
}
static void parameters_changed(struct crypt_state * s)
{
    switch(s->action.current)
    {
        case 0:
            encrypt(s);
            data_changed(&(s->output));
            split_output(&(s->output), 42);
            break;
        case 1:
            decrypt(s);
            data_changed(&(s->input));
            data_changed(&(s->iv));
            break;
    }
    
}
static void action_changed(struct crypt_state * s)
{
    switch(s->action.current)
    {
        case 0:
            memset(s->output.data, 0, s->output.max_size);
            s->output.data_len = 0;
            data_changed(&(s->output));
            break;
        case 1:
            memset(s->input.data, 0, s->input.max_size);
            s->input.data_len = 0;
            data_changed(&(s->input));
            break;
    }
    
}
static void update_parameters(struct crypt_state * s)
{
    set_parameters(s->cipher.options[s->cipher.current],
                   s->mode.options[s->mode.current], s->key.data_len,
                   string_to_int(s->round.options[s->round.current], 10), &(s->p));
    validate_parameters(&(s->p));
    s->iv.enabled = s->p.has_iv;

    parameters_changed(s);
}
static void update_crypt_state(struct crypt_state * s)
{
    int cipher_changed = s->cipher.old != s->cipher.current;
    int cipher = find_cipher(s->cipher.options[s->cipher.current]);
    int key_size_changed = s->key_size.old != s->key_size.current;
    if(cipher_changed)
    {
        s->iv.data_len = get_block_size(cipher);
        data_changed(&(s->iv));
        s->key_size.current = 0;
        get_key_ranges(cipher, &(s->key_size.options), &(s->key_size.len));
    }
    if((cipher_changed) || (key_size_changed))
    {
        s->key.data_len = string_to_int(s->key_size.options[s->key_size.current], 10);
        data_changed(&(s->key));
        s->round.current = 0;
        get_round_ranges(cipher, s->key.data_len, &(s->round.options), &(s->round.len));
    }

    int update = 0;
    for(int i = 0; i < s->combo_list_size; i++)
    {
        struct state_combo * a = s->combo_list[i];
        if(!a->enabled) continue;
        if(a->old != a->current)
        {
            if(a->idx == ACTION)
            {
                action_changed(s);
            }
            a->old = a->current;
            update = 1;
        }
    }
    for(int i = 0; i < s->string_list_size; i++)
    {
        struct state_string * a = s->string_list[i];
        if(!a->enabled) continue;
        if(a->old_base != a->base) {
            data_changed(a);
        }
        a->old_base = a->base;
        memset(a->display + a->display_len, 0, a->max_size - a->display_len);
        if(strcmp(a->display, a->old_display) != 0)
        {
            display_changed(a);
            update = 1;
            memset(a->old_display, 0, sizeof(char)*a->max_size);
            strcpy(a->old_display, a->display);
        }
    }
    if(update)
        update_parameters(s);

    for(int i = 0; i < s->string_list_size; i++)
    {
        struct state_string * a = s->string_list[i];
        memset(a->old_display, 0, sizeof(char)*a->max_size);
        strcpy(a->old_display, a->display);
    }
}
static int init_state_string(struct state_string * s, int idx, int base, int has_ascii, struct state_string *** list)
{
    static int index = 0;
    if(s == NULL)
        return index;

    *s = (struct state_string){calloc(sizeof(char),INITIAL_SIZE), calloc(sizeof(char),INITIAL_SIZE), calloc(sizeof(char),INITIAL_SIZE),
                               idx, 0, 0, base, -1, has_ascii, 1, INITIAL_SIZE, 1, idx != INPUT && idx != OUTPUT};
    (*list)[index] = s;
    index++;
    *list = realloc(*list, sizeof(struct state_string*)*(index+2));
    return index;
}
static int init_state_combo(struct state_combo * s, int idx, int def, struct state_combo *** list)
{
    static int index = 0;
    if(s == NULL)
        return index;
    *s = (struct state_combo){idx, -1, 0, def, NULL, 0, 1};
    (*list)[index] = s;
    index++;
    *list = realloc(*list, sizeof(struct state_combo*)*(index+2));
    return index;
}
static void init_crypt_state(struct crypt_state * s)
{
        s->combo_list = malloc(sizeof(struct state_combo*));
        init_state_combo(&(s->cipher), CIPHER, 0, &(s->combo_list));
        init_state_combo(&(s->mode), MODE, 0, &(s->combo_list));
        init_state_combo(&(s->key_size), KEY_SIZE, 2, &(s->combo_list));
        init_state_combo(&(s->round), ROUNDS, 0, &(s->combo_list));
        init_state_combo(&(s->action), ACTION, 0, &(s->combo_list));
        s->combo_list_size = init_state_combo(NULL, 0, 0, NULL);

        s->string_list = malloc(sizeof(struct state_string*));
        init_state_string(&(s->input), INPUT, 3, 1, &(s->string_list));
        init_state_string(&(s->output), OUTPUT, 0, 0, &(s->string_list));
        init_state_string(&(s->key), KEY, 0, 1, &(s->string_list));
        init_state_string(&(s->iv), IV, 0, 0, &(s->string_list));
        s->string_list_size = init_state_string(NULL, 0, 0, 0, NULL);

        get_cipher_list(&(s->cipher.options), &(s->cipher.len));
        get_mode_list(&(s->mode.options), &(s->mode.len));

        update_crypt_state(s);

        for(int i = 0; i < s->combo_list_size; i++)
        {
            s->combo_list[i]->current = s->combo_list[i]->def;
        }
}
static void free_crypt_state(struct crypt_state * s)
{
    for(int i = 0; i < s->combo_list_size; i++)
    {
        free(s->combo_list[i]->options);
    }
    for(int i = 0; i < s->string_list_size; i++)
    {
        free(s->string_list[i]->data);
        free(s->string_list[i]->display);
        free(s->string_list[i]->old_display);
    }
    free(s->combo_list);
    free(s->string_list);
}
static void inactive_combobox(struct nk_context *ctx, const char * buffer)
{
    struct nk_style_combo combo;
    combo = ctx->style.combo;
    ctx->style.combo = inactive_combo_style(ctx);
    if(nk_combo_begin_label(ctx, buffer, nk_vec2(0,0))){
        nk_combo_end(ctx);
    }
    ctx->style.combo = combo;
}
static void inactive_button(struct nk_context *ctx, const char * buffer)
{
    struct nk_style_button button;
    button = ctx->style.button;
    ctx->style.button = inactive_button_style(ctx);
    nk_button_label(ctx, buffer);
    ctx->style.button = button;
}
static void inactive_label(struct nk_context *ctx, const char * buffer)
{   
    nk_label_colored(ctx, buffer, NK_TEXT_CENTERED, nk_rgb(60, 60, 60));
}
static void draw_state_combo(struct nk_context *ctx, struct state_combo * c)
{
    if(c->enabled)
    {
        nk_label(ctx, labels[c->idx], NK_TEXT_CENTERED);
        c->current = nk_combo(ctx, c->options, c->len, c->current, 25, nk_vec2(200,200));
    } else {
        inactive_label(ctx, labels[c->idx]);
        inactive_combobox(ctx, c->options[c->current]);
    }
}
static void draw_state_string(struct nk_context *ctx, struct state_string * s)
{
    if(!nk_window_has_focus(ctx))
            ctx->current->edit.active = 0;
    nk_flags f = NK_EDIT_FIELD;
    if(s->enabled)
    {
        nk_label(ctx, labels[s->idx], NK_TEXT_CENTERED);
        nk_edit_string(ctx, f, s->display, &(s->display_len), s->max_size, base_filter[s->base]);
    } else {
        inactive_label(ctx, labels[s->idx]);
        f &= NK_EDIT_READ_ONLY;
        struct nk_style_edit edit;
        edit = ctx->style.edit;
        ctx->style.edit = inactive_edit_style(ctx);
        nk_edit_string(ctx, f, s->display, &(s->display_len), s->max_size, base_filter[s->base]);
        ctx->style.edit = edit;
    }

    if(s->enabled)
    {
        s->base = nk_combo(ctx, base_strings, 3, s->base, 25, nk_vec2(200,200));
        if(nk_button_label(ctx, "New")){
            prng(s->data, s->data_len);
            data_changed(s);
        }
    } else {
        inactive_combobox(ctx, base_strings[s->base]);
        inactive_button(ctx, "New");
    }

}

static void input_window(struct nk_context *ctx, struct nk_rect win, int margin, struct crypt_state * s) {
    if (nk_begin(ctx, "Input", win, NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR))
    {
        if(!nk_window_has_focus(ctx))
            ctx->current->edit.active = 0;
        nk_layout_row_dynamic(ctx, 25, 2);
        nk_label(ctx, labels[s->input.idx], NK_TEXT_CENTERED);
        s->input.base = nk_combo(ctx, base_strings, 4, s->input.base, 25, nk_vec2(200,200));
        nk_layout_row_dynamic(ctx, win.h - margin - 10 - 25, 1);
        ctx->text_edit.string.buffer.type = NK_BUFFER_DYNAMIC;
        int old = s->input.display_len;
        nk_edit_string(ctx, NK_EDIT_BOX|NK_EDIT_MULTILINE, s->input.display, &(s->input.display_len), s->input.max_size, base_filter[s->input.base]);
        if(s->input.display_len > s->input.max_size)
        {
            check_resize(&(s->input));
            s->input.display_len = old;
        } 
    }
    nk_end(ctx);
}
static void output_window(struct nk_context *ctx, struct nk_rect win, int margin, struct crypt_state * s) {
    if (nk_begin(ctx, "Output", win, NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR))
    {
        if(!nk_window_has_focus(ctx))
            ctx->current->edit.active = 0;
        nk_layout_row_dynamic(ctx, 25, 2);
        nk_label(ctx, labels[s->output.idx], NK_TEXT_CENTERED);
        s->output.base = nk_combo(ctx, base_strings, 4, s->output.base, 25, nk_vec2(200,200));
        nk_layout_row_dynamic(ctx, win.h - margin - 10 - 25, 1);
        int old = s->output.display_len;
        nk_edit_string(ctx, NK_EDIT_BOX|NK_EDIT_MULTILINE, s->output.display, &(s->output.display_len), s->output.max_size, base_filter[s->input.base]);     
        if(s->output.display_len > s->output.max_size)
        {
            check_resize(&(s->output));
            s->output.display_len = old;
        } 
        check_resize(&(s->output));  
    }
    nk_end(ctx);
}


const char * actions[] = {
    "Encrypt",
    "Decrypt",
};
const char * states[] = {
    "OK",
    "ERROR",
};
static void status_window(struct nk_context *ctx, struct nk_rect win, int margin, struct crypt_state * s) {
    if (nk_begin(ctx, "Status", win, NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR))
    {
        int row_height = 20;
        nk_layout_row_dynamic(ctx, 30, 1);
        nk_label(ctx, labels[s->action.idx], NK_TEXT_CENTERED);
        s->action.current = nk_combo(ctx, actions, 2, s->action.current, 25, nk_vec2(200,200));
        nk_layout_row_dynamic(ctx, 30, 1);
        nk_label(ctx, "Parameters", NK_TEXT_CENTERED);
        nk_group_begin(ctx, "a", NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR);
            nk_layout_row_dynamic(ctx, row_height, 2);
            nk_label(ctx, labels[s->cipher.idx], NK_TEXT_CENTERED);
            nk_label(ctx, s->p.cipher, NK_TEXT_CENTERED);
        nk_group_end(ctx);
        nk_group_begin(ctx, "b", NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR);
            nk_layout_row_dynamic(ctx, row_height, 2);
            nk_label(ctx, labels[s->mode.idx], NK_TEXT_CENTERED);
            nk_label(ctx, s->p.mode, NK_TEXT_CENTERED);
        nk_group_end(ctx);
        nk_group_begin(ctx, "c", NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR);
            nk_layout_row_dynamic(ctx, row_height, 2);
            nk_label(ctx, labels[s->key_size.idx], NK_TEXT_CENTERED);
            nk_labelf(ctx, NK_TEXT_CENTERED, "%d", s->p.key_size);
        nk_group_end(ctx);
        nk_group_begin(ctx, "d", NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR);
            nk_layout_row_dynamic(ctx, row_height, 2);
            nk_label(ctx, labels[s->round.idx], NK_TEXT_CENTERED);
            nk_labelf(ctx, NK_TEXT_CENTERED, "%d", s->p.rounds);
        nk_group_end(ctx);
        nk_group_begin(ctx, "e", NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR);
            nk_layout_row_dynamic(ctx, row_height, 2);
            nk_label(ctx, "Block Size", NK_TEXT_CENTERED);
            nk_labelf(ctx, NK_TEXT_CENTERED, "%d", s->p.block_size);
        nk_group_end(ctx);
        nk_group_begin(ctx, "f", NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR);
            nk_layout_row_dynamic(ctx, row_height, 2);
            nk_label(ctx, "IV", NK_TEXT_CENTERED);
            nk_labelf(ctx, NK_TEXT_CENTERED, "%s", s->iv.enabled ? "True" : "False");
        nk_group_end(ctx);
        nk_group_begin(ctx, "h", NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR);
            nk_layout_row_dynamic(ctx, row_height, 2);
            nk_label(ctx, "Plain Text", NK_TEXT_CENTERED);
            nk_labelf(ctx, NK_TEXT_CENTERED, "%d", s->input.data_len);
        nk_group_end(ctx);
        nk_group_begin(ctx, "i", NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR);
            nk_layout_row_dynamic(ctx, row_height, 2);
            nk_label(ctx, "Cipher Text", NK_TEXT_CENTERED);
            nk_labelf(ctx, NK_TEXT_CENTERED, "%d", s->output.data_len);
        nk_group_end(ctx);
    
        nk_layout_row_dynamic(ctx, 80, 1);
        nk_spacing(ctx, 1);
        nk_layout_row_dynamic(ctx, 30, 1);
        nk_label(ctx, "Status", NK_TEXT_CENTERED);
        nk_layout_row_dynamic(ctx, 30, 1);
        nk_group_begin(ctx, "z", NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR);
            nk_layout_row_dynamic(ctx, row_height, 1);
            nk_label(ctx, states[s->state], NK_TEXT_CENTERED);
        nk_group_end(ctx);
    }
    nk_end(ctx);
}
static void options_window(struct nk_context *ctx, struct nk_rect win, int margin, struct crypt_state * s) {
    int group_height = win.h/3 - 7; //muh padding
    int row_height = win.h/3 - 16; //muh padding
    float gap = 0.001;
    if (nk_begin(ctx, "Options", win, NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR))
    {
        nk_layout_row(ctx, NK_DYNAMIC, group_height, 4, (float[]){0.25f, 0.25f, 0.25f, 0.25f - gap});

        nk_group_begin(ctx, "1", NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR);
            nk_layout_row(ctx, NK_DYNAMIC, row_height, 2, (float[]){0.25f, 0.75f});
            draw_state_combo(ctx, &(s->cipher));
        nk_group_end(ctx);
        nk_group_begin(ctx, "2", NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR);
            nk_layout_row(ctx, NK_DYNAMIC, row_height, 2, (float[]){0.2f, 0.8f});
            draw_state_combo(ctx, &(s->mode));
        nk_group_end(ctx);
        nk_group_begin(ctx, "3", NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR);
            nk_layout_row(ctx, NK_DYNAMIC, row_height, 2, (float[]){0.35f, 0.65f});
            draw_state_combo(ctx, &(s->key_size));
        nk_group_end(ctx);
        nk_group_begin(ctx, "4", NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR);
            nk_layout_row(ctx, NK_DYNAMIC, row_height, 2, (float[]){0.3f, 0.7f});
            draw_state_combo(ctx, &(s->round));
        nk_group_end(ctx);

        nk_layout_row(ctx, NK_DYNAMIC, group_height, 1, (float[]){1.0f - gap});
        nk_group_begin(ctx, "10", NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR);
            nk_layout_row(ctx, NK_DYNAMIC, row_height, 4, (float[]){0.05f - gap, 0.755f, 0.1f, 0.096f});
            draw_state_string(ctx, &(s->iv));
        nk_group_end(ctx);

        nk_layout_row(ctx, NK_DYNAMIC, group_height, 1, (float[]){1.0f - gap});
        nk_group_begin(ctx, "11", NK_WINDOW_BORDER|NK_WINDOW_NO_SCROLLBAR);
            nk_layout_row(ctx, NK_DYNAMIC, row_height, 4, (float[]){0.05f - gap, 0.755f, 0.1f, 0.096f});
            draw_state_string(ctx, &(s->key));
        nk_group_end(ctx);
    }
    nk_end(ctx);
}
static inline void scale(struct nk_rect* win, int width, int height, int margin)
{
    *win = nk_rect(win->x*width + margin/2, win->y*height + margin/2,
                   win->w*width - margin, win->h*height - margin);
}
static void all(struct nk_context *ctx, int width, int height, int margin, struct crypt_state * s) {
        float status_w = 0.2f;
    float options_h = 0.2f;

    struct nk_rect options = nk_rect(0, 0, 1, options_h);
    struct nk_rect status = nk_rect(0.5-status_w/2, options.h, status_w, 1-options.h);
    struct nk_rect input = nk_rect(0, options.h, status.x, 1-options.h);
    struct nk_rect output = nk_rect(0.5+status.w/2, options.h, status.x, 1-options.h);

    
    scale(&options, width, height, margin);
    scale(&status, width, height, margin);
    scale(&input, width, height, margin);
    scale(&output, width, height, margin);

    input_window(ctx, input, margin, s);
    output_window(ctx, output, margin, s);
    status_window(ctx, status, margin, s);
    options_window(ctx, options, margin, s);
}

int loop()
{
    static struct nk_context *ctx;
    static struct nk_glfw glfw;
    static GLFWwindow *win;
    static int width = 0, height = 0;
    setup_gui(&ctx, &glfw, &win, &width, &height);
    
    struct crypt_state s = {0};
    init_crypt_state(&s);
    update_crypt_state(&s);

    printf("Ready\n");

    while (!glfwWindowShouldClose(win))
    {
        nk_input_begin(ctx);
        glfwPollEvents();
        nk_glfw3_new_frame(&glfw);

        all(ctx, width, height, 10, &s);
        update_crypt_state(&s);


        glfwGetWindowSize(win, &width, &height);
        glViewport(0, 0, width, height);
        glClear(GL_COLOR_BUFFER_BIT);
        glClearColor(0.2, 0.2, 0.2, 1.0f);

        nk_glfw3_render(&glfw, NK_ANTI_ALIASING_ON, MAX_VERTEX_BUFFER, MAX_ELEMENT_BUFFER);
        glfwSwapBuffers(win);
        nk_input_end(ctx);
    }
    printf("Free\n");
    free_crypt_state(&s);
    nk_glfw3_shutdown(&glfw);
    glfwTerminate();
    return 0;
}