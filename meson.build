project(
    'ioannes',
    ['c', 'cpp'],
    version: '0.1.0',
    meson_version: '>=1.1.0',
    default_options: [
        'backend=ninja',
        'c_std=c23',
        'cpp_std=c++23',
        'default_library=static',
        'b_ndebug=if-release',
        'warning_level=2',
    ],
)

cmake = import('cmake')

src_root = meson.project_source_root()
build_root = meson.project_build_root()

is_debug = get_option('debug')

dll_sources = [
    'dll/dll.cpp',
    'dll/patches.cpp',
    'dll/gui.cpp',

    'dll/thirdparty/ImGuiColorTextEdit/TextEditor.cpp',
    'dll/thirdparty/kiero/kiero.cpp',
]

dll_inc = include_directories(
    [
        'dll',
        'proxy/libproxy',
        'dll/thirdparty/Pattern16',
        'dll/thirdparty/kiero',
        'dll/thirdparty/ImGuiColorTextEdit',
        'dll/thirdparty/imgui_memory_editor',
        'dll/thirdparty/IconFontCppHeaders',
    ],
)

dll_link_args = [
    src_root + '/proxy/libproxy/libproxy.a',
    src_root + '/dll/exports.def',
]

proj_args = [
    '-DIOANNES_VERSION="@0@"'.format(meson.project_version()),
]

if get_option('no_sigscans')
    proj_args += '-DNO_SIGSCANS=1'
endif
if get_option('logfile')
    proj_args += '-DLOGFILE=1'
endif
if get_option('dump_aes_decrypt')
    proj_args += '-DDUMP_AES_DECRYPT=1'
endif

add_project_arguments(proj_args, language: ['c', 'cpp'])

global_args = [
    '-fmacro-prefix-map=' + src_root + '/=',
    '-fmacro-prefix-map=' + build_root + '/../=',
    '-fmacro-prefix-map=../=',

    '-DULOG_BUILD_COLOR=0',
    '-DULOG_BUILD_TIME=1',
    '-DULOG_BUILD_DYNAMIC_CONFIG=1',
    '-DULOG_BUILD_EXTRA_OUTPUTS=1',
]
if is_debug
    global_args += ['-DULOG_BUILD_SOURCE_LOCATION=1']
else
    global_args += '-DULOG_BUILD_SOURCE_LOCATION=0'
endif

add_global_arguments(global_args, language: ['c', 'cpp'])

global_link_args = [
    '-static',
    '-static-libgcc',
    '-static-libstdc++',
    '-lstdc++exp',

    '-ld3d11',
    '-ldxgi',
    '-luuid',

    '-mavx2',
    '-mlzcnt',
    '-mbmi',
    '-mbmi2',
]
add_global_arguments(global_link_args, language: ['c', 'cpp'])
add_global_link_arguments(global_link_args, language: ['c', 'cpp'])

microlog_dep = subproject('microlog').get_variable('microlog_dep')
xxhash_dep = subproject('xxhash', default_options: ['cli=false', 'xxh3=true']).get_variable('xxhash_dep')
fmt_dep = subproject('fmt', default_options: ['header-only=true']).get_variable('fmt_header_only_dep')
imgui_dep = dependency('imgui', default_options: ['dx11=enabled', 'win=enabled'])
jansson_dep = dependency('jansson')

safetyhook_proj = cmake.subproject('safetyhook')
safetyhook_dep = safetyhook_proj.dependency('safetyhook')
zydis_dep = safetyhook_proj.dependency('Zydis')

# TODO: Port kiero to use safetyhook, or replace it entirely for our own thing
minhook_proj = cmake.subproject('minhook')
minhook_dep = minhook_proj.dependency('minhook')

dll_deps = [
    microlog_dep,
    imgui_dep,
    jansson_dep,
    xxhash_dep,
    fmt_dep,
    safetyhook_dep,
    zydis_dep,
    minhook_dep,
]

custom_targets = []

shared_library(
    'ioannes',
    sources: [
        dll_sources,
        custom_targets,
    ],
    include_directories: dll_inc,
    dependencies: dll_deps,
    name_prefix: '',
    link_args: dll_link_args,
)
