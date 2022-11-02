<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Title
    |--------------------------------------------------------------------------
    |
    | Here you can change the default title of your admin panel.
    |
    | For detailed instructions you can look the title section here:
    | https://github.com/jeroennoten/Laravel-AdminLTE/wiki/Basic-Configuration
    |
    */

    'title' => 'SIM RSUD Waled',
    'title_prefix' => '',
    'title_postfix' => '',

    /*
    |--------------------------------------------------------------------------
    | Favicon
    |--------------------------------------------------------------------------
    |
    | Here you can activate the favicon.
    |
    | For detailed instructions you can look the favicon section here:
    | https://github.com/jeroennoten/Laravel-AdminLTE/wiki/Basic-Configuration
    |
    */

    'use_ico_only' => true,
    'use_full_favicon' => false,

    /*
    |--------------------------------------------------------------------------
    | Logo
    |--------------------------------------------------------------------------
    |
    | Here you can change the logo of your admin panel.
    |
    | For detailed instructions you can look the logo section here:
    | https://github.com/jeroennoten/Laravel-AdminLTE/wiki/Basic-Configuration
    |
    */

    'logo' => '<b>SIMRS Waled</b>',
    'logo_img' => 'vendor/adminlte/dist/img/rswaledico.png',
    'logo_img_class' => 'brand-image',
    'logo_img_xl' => null,
    'logo_img_xl_class' => 'brand-image-xs',
    'logo_img_alt' => 'SIMRS Waled',

    /*
    |--------------------------------------------------------------------------
    | User Menu
    |--------------------------------------------------------------------------
    |
    | Here you can activate and change the user menu.
    |
    | For detailed instructions you can look the user menu section here:
    | https://github.com/jeroennoten/Laravel-AdminLTE/wiki/Basic-Configuration
    |
    */

    'usermenu_enabled' => true,
    'usermenu_header' => false,
    'usermenu_header_class' => 'bg-primary',
    'usermenu_image' => false,
    'usermenu_desc' => false,
    'usermenu_profile_url' => false,

    /*
    |--------------------------------------------------------------------------
    | Layout
    |--------------------------------------------------------------------------
    |
    | Here we change the layout of your admin panel.
    |
    | For detailed instructions you can look the layout section here:
    | https://github.com/jeroennoten/Laravel-AdminLTE/wiki/Layout-and-Styling-Configuration
    |
    */

    'layout_topnav' => null,
    'layout_boxed' => null,
    'layout_fixed_sidebar' => null,
    'layout_fixed_navbar' => null,
    'layout_fixed_footer' => null,
    'layout_dark_mode' => null,

    /*
    |--------------------------------------------------------------------------
    | Authentication Views Classes
    |--------------------------------------------------------------------------
    |
    | Here you can change the look and behavior of the authentication views.
    |
    | For detailed instructions you can look the auth classes section here:
    | https://github.com/jeroennoten/Laravel-AdminLTE/wiki/Layout-and-Styling-Configuration
    |
    */

    'classes_auth_card' => 'card-outline card-primary',
    'classes_auth_header' => '',
    'classes_auth_body' => '',
    'classes_auth_footer' => '',
    'classes_auth_icon' => '',
    'classes_auth_btn' => 'btn-flat btn-primary',

    /*
    |--------------------------------------------------------------------------
    | Admin Panel Classes
    |--------------------------------------------------------------------------
    |
    | Here you can change the look and behavior of the admin panel.
    |
    | For detailed instructions you can look the admin panel classes here:
    | https://github.com/jeroennoten/Laravel-AdminLTE/wiki/Layout-and-Styling-Configuration
    |
    */

    'classes_body' => 'text-sm',
    'classes_brand' => '',
    'classes_brand_text' => '',
    'classes_content_wrapper' => '',
    'classes_content_header' => '',
    'classes_content' => '',
    'classes_sidebar' => 'sidebar-dark-primary elevation-4',
    'classes_sidebar_nav' => '',
    'classes_topnav' => 'navbar-white navbar-light',
    'classes_topnav_nav' => 'navbar-expand',
    'classes_topnav_container' => 'container',

    /*
    |--------------------------------------------------------------------------
    | Sidebar
    |--------------------------------------------------------------------------
    |
    | Here we can modify the sidebar of the admin panel.
    |
    | For detailed instructions you can look the sidebar section here:
    | https://github.com/jeroennoten/Laravel-AdminLTE/wiki/Layout-and-Styling-Configuration
    |
    */

    'sidebar_mini' => 'lg',
    'sidebar_collapse' => false,
    'sidebar_collapse_auto_size' => false,
    'sidebar_collapse_remember' => false,
    'sidebar_collapse_remember_no_transition' => true,
    'sidebar_scrollbar_theme' => 'os-theme-light',
    'sidebar_scrollbar_auto_hide' => 'l',
    'sidebar_nav_accordion' => false,
    'sidebar_nav_animation_speed' => 300,

    /*
    |--------------------------------------------------------------------------
    | Control Sidebar (Right Sidebar)
    |--------------------------------------------------------------------------
    |
    | Here we can modify the right sidebar aka control sidebar of the admin panel.
    |
    | For detailed instructions you can look the right sidebar section here:
    | https://github.com/jeroennoten/Laravel-AdminLTE/wiki/Layout-and-Styling-Configuration
    |
    */

    'right_sidebar' => false,
    'right_sidebar_icon' => 'fas fa-cogs',
    'right_sidebar_theme' => 'dark',
    'right_sidebar_slide' => true,
    'right_sidebar_push' => true,
    'right_sidebar_scrollbar_theme' => 'os-theme-light',
    'right_sidebar_scrollbar_auto_hide' => 'l',

    /*
    |--------------------------------------------------------------------------
    | URLs
    |--------------------------------------------------------------------------
    |
    | Here we can modify the url settings of the admin panel.
    |
    | For detailed instructions you can look the urls section here:
    | https://github.com/jeroennoten/Laravel-AdminLTE/wiki/Basic-Configuration
    |
    */

    'use_route_url' => false,
    'dashboard_url' => 'home',
    'logout_url' => 'logout',
    'login_url' => 'login',
    'register_url' => false,
    'password_reset_url' => 'password/reset',
    'password_email_url' => 'password/email',
    'profile_url' => false,

    /*
    |--------------------------------------------------------------------------
    | Laravel Mix
    |--------------------------------------------------------------------------
    |
    | Here we can enable the Laravel Mix option for the admin panel.
    |
    | For detailed instructions you can look the laravel mix section here:
    | https://github.com/jeroennoten/Laravel-AdminLTE/wiki/Other-Configuration
    |
    */

    'enabled_laravel_mix' => false,
    'laravel_mix_css_path' => 'css/app.css',
    'laravel_mix_js_path' => 'js/app.js',

    /*
    |--------------------------------------------------------------------------
    | Menu Items
    |--------------------------------------------------------------------------
    |
    | Here we can modify the sidebar/top navigation of the admin panel.
    |
    | For detailed instructions you can look here:
    | https://github.com/jeroennoten/Laravel-AdminLTE/wiki/Menu-Configuration
    |
    */

    'menu' => [
        // Navbar items:
        [
            'type'         => 'navbar-search',
            'text'         => 'search',
            'topnav_right' => true,
        ],
        [
            'type'         => 'fullscreen-widget',
            'topnav_right' => true,
        ],

        // Sidebar items:
        [
            'type' => 'sidebar-menu-search',
            'text' => 'search',
        ],
        ['header' => 'MENU UTAMA'],
        [
            'text'        => 'Landing Page',
            'url'         => '',
            'icon'        => 'fas fa-home',
        ],
        [
            'text'        => 'Dashboard',
            'url'         => 'home',
            'icon'        => 'fas fa-home',
        ],
        //MENU INFO
        [
            'text'        => 'Menu Informasi Umum',
            'icon'        => 'fas fa-info-circle',
            'submenu' => [
                [
                    'text' => 'Daftar Pasien',
                    'icon'    => 'fas fa-user-plus',
                    'shift'   => 'ml-2',
                    'url'  => 'daftar_pasien',
                    // 'can' => 'admin',
                ],
                [
                    'text' => 'Jadwal Dokter Poliklinik',
                    'icon'    => 'fas fa-calendar-alt',
                    'shift'   => 'ml-2',
                    'url'  => 'info_jadwaldokter',
                    // 'can' => 'admin',
                ],
                [
                    'text' => 'Jadwal Libur Poliklinik',
                    'icon'    => 'fas fa-calendar-times',
                    'shift'   => 'ml-2',
                    'url'  => 'info_jadwallibur',
                ],
                [
                    'text' => 'Jadwal Operasi',
                    'icon'    => 'fas fa-calendar-alt',
                    'shift'   => 'ml-2',
                    'url'  => 'info_jadwaloperasi',
                    // 'can' => 'admin',
                ],

                // [
                //     'text' => 'Status Antrian',
                //     'icon'    => 'fas fa-sign-in-alt',
                //     'url'  => 'info/antrian',
                //     'shift'   => 'ml-2',
                // ],
                // [
                //     'text' => 'Info Poliklinik',
                //     'icon'    => 'fas fa-clinic-medical',
                //     'shift'   => 'ml-2',
                //     'url'  => 'info/poliklinik',
                // ],
                // [
                //     'text' => 'Jadwal Poliklinik',
                //     'icon'    => 'fas fa-calendar-alt',
                //     'url'  => 'info/jadwal_poliklinik',
                //     'shift'   => 'ml-2',
                // ],
                // [
                //     'text' => 'Jadwal Libur Poliklinik',
                //     'icon'    => 'fas fa-calendar-times',
                //     'shift'   => 'ml-2',
                //     'url'  => 'info/jadwal_poli_libur',
                // ],
            ]
        ],
        // MENU APLIKASI ANTRIAN
        [
            'text'    => 'Aplikasi Antrian',
            'icon'    => 'fas fa-sign-in-alt',
            'can' => ['admin', 'pendaftaran', 'kasir', 'poliklinik', 'farmasi'],
            'submenu' => [
                [
                    'text' => 'Console Antrian',
                    'icon'    => 'fas fa-desktop',
                    'url'  => 'antrian/console',
                    'shift'   => 'ml-2',
                    'can' => 'admin',
                ],
                [
                    'text' => 'Status TaskId Antrian',
                    'icon'    => 'fas fa-desktop',
                    'url'  => 'antrian/taskid',
                    'shift'   => 'ml-2',
                    'can' => 'admin',
                ],
                // [
                //     'text' => 'Antrian Pendaftaran WA',
                //     'icon'    => 'fas fa-user-plus',
                //     'url'  => 'antrianwa',
                //     'shift'   => 'ml-2',
                //     'can' => 'pendaftaran',
                // ],
                [
                    'text' => 'Antrian Pendaftaran',
                    'icon'    => 'fas fa-user-plus',
                    'url'  => 'antrian/pendaftaran',
                    'shift'   => 'ml-2',
                    'can' => 'pendaftaran',
                ],
                [
                    'text' => 'Antrian Pembayaran',
                    'icon'    => 'fas fa-cash-register',
                    'url'  => 'antrian/pembayaran',
                    'shift'   => 'ml-2',
                    'can' => 'kasir',
                ],
                [
                    'text' => 'Antrian Poliklinik',
                    'icon'    => 'fas fa-clinic-medical',
                    'url'  => 'antrian/poli',
                    'shift'   => 'ml-2',
                    'can' => 'poliklinik',
                ],
                [
                    'text' => 'Surat Kontrol Poliklinik',
                    'icon'    => 'fas fa-file-medical',
                    'url'  => 'antrian/surat_kontrol_poli',
                    'shift'   => 'ml-2',
                    'can' => 'poliklinik',
                ],
                [
                    'text' => 'KPO Elektronik',
                    'icon'    => 'fas fa-pills',
                    'url'  => 'antrian/kpo',
                    'shift'   => 'ml-2',
                    'can' => 'poliklinik',
                ],
                [
                    'text' => 'Laporan Kunjungan Poliklinik',
                    'icon'    => 'fas fa-chart-line',
                    'shift'   => 'ml-2',
                    'url'  => 'antrian/laporan_kunjungan_poliklinik',
                    'can' => 'poliklinik',
                ],
                [
                    'text' => 'Antrian Farmasi',
                    'icon'    => 'fas fa-pills',
                    'url'  => 'antrian/farmasi',
                    'shift'   => 'ml-2',
                    'can' => 'farmasi',
                ],
                // [
                //     'text' => 'Display Antrian Pendaftaran',
                //     'icon'    => 'fas fa-user-plus',
                //     'url'  => 'antrian/display_pendaftaran',
                //     'shift'   => 'ml-2',
                //     'can' => 'admin',
                // ],
                [
                    'text' => 'Laporan Antrian',
                    'icon'    => 'fas fa-chart-line',
                    'shift'   => 'ml-2',
                    'url'  => 'antrian/laporan',
                    // 'can' => 'admin',
                ],
                [
                    'text' => 'Laporan Pertanggal',
                    'icon'    => 'fas fa-chart-line',
                    'shift'   => 'ml-2',
                    'url'  => 'antrian/laporan_tanggal',
                    // 'can' => 'admin',
                ],
                [
                    'text' => 'Laporan Perbulan',
                    'icon'    => 'fas fa-chart-line',
                    'shift'   => 'ml-2',
                    'url'  => 'antrian/laporan_bulan',
                    // 'can' => 'admin',
                ],
            ],
        ],
        // MENU VCLAIM
        [
            'text'    => 'VClaim BPJS',
            'icon'    => 'fas fa-sign-in-alt',
            'can' => 'bpjs',
            'submenu' => [
                [
                    'text' => 'Monitoring Pelayanan Peserta',
                    'icon'    => 'fas fa-id-card',
                    'url'  => 'vclaim/monitoring_pelayanan_peserta',
                    'shift'   => 'ml-2',
                    'can' => 'bpjs',
                ],
                [
                    'text' => 'SEP Internal',
                    'icon'    => 'fas fa-id-card',
                    'url'  => 'vclaim/sep_internal',
                    'shift'   => 'ml-2',
                    'can' => 'bpjs',
                ],
                [
                    'text' => 'Rujukan',
                    'icon'    => 'fas fa-id-card',
                    'url'  => 'vclaim/rujukan',
                    'shift'   => 'ml-2',
                    'can' => 'bpjs',
                ],
                [
                    'text' => 'Data Surat Kontrol',
                    'icon'    => 'fas fa-id-card',
                    'url'  => 'vclaim/data_surat_kontrol',
                    'shift'   => 'ml-2',
                    'can' => 'bpjs',
                ],
            ],
        ],
        // PELAYANAN MEDIS
        [
            'text' => 'Pelayanan Medis',
            'icon'    => 'fas fa-stethoscope',
            'can' => 'pelayanan-medis',
            'submenu' => [
                [
                    'text' => 'Poliklinik',
                    'icon'    => 'fas fa-clinic-medical',
                    'url'  => 'poli',
                    'shift'   => 'ml-2',
                    'can' => 'pelayanan-medis',
                ],
                [
                    'text' => 'Dokter',
                    'icon'    => 'fas fa-user-md',
                    'url'  => 'dokter',
                    'shift'   => 'ml-2',
                    'can' => 'pelayanan-medis',
                ],
                [
                    'text' => 'Jadwal Dokter Poliklinik',
                    'icon'    => 'fas fa-calendar-alt',
                    'shift'   => 'ml-2',
                    'url'  => 'jadwaldokter',
                    'can' => 'pelayanan-medis',
                ],
                [
                    'text' => 'Jadwal Libur Poliklinik',
                    'icon'    => 'fas fa-calendar-times',
                    'shift'   => 'ml-2',
                    'url'  => 'jadwallibur',
                    // 'active'  => ['pelayananmedis/jadwal_poli_libur', 'regex:@^pelayananmedis/jadwal_poli_libur(\/[0-9]+)?+$@', 'regex:@^pelayananmedis/jadwal_poli_libur(\/[0-9]+)?\/edit+$@',  'pelayananmedis/jadwal_poli_libur/create'],
                    'can' => ['pelayanan-medis'],
                ],
                [
                    'text' => 'Jadwal Opersi',
                    'icon'    => 'fas fa-calendar-alt',
                    'shift'   => 'ml-2',
                    'url'  => 'jadwaloperasi',
                    'can' => 'pelayanan-medis',
                ],
                [
                    'text' => 'Tarif Layanan',
                    'icon'    => 'fas fa-hand-holding-medical',
                    'url'  => 'tarif_layanan',
                    'shift'   => 'ml-2',
                    'can' => 'pelayanan-medis',
                ],
                [
                    'text' => 'Tarif Kelompok Layanan',
                    'icon'    => 'fas fa-hand-holding-medical',
                    'url'  => 'tarif_kelompok_layanan',
                    'shift'   => 'ml-2',
                    'can' => 'pelayanan-medis',
                ],

            ],
        ],
        // REKAM MEDIS
        [
            'text' => 'Rekam Medis',
            'icon'    => 'fas fa-file-medical',
            'can' => 'rekam-medis',
            'submenu' => [
                [
                    'text' => 'Kunjungan',
                    'icon'    => 'fas fa-hospital-user',
                    'url'  => 'kunjungan',
                    'shift'   => 'ml-2',
                    'can' => 'rekam-medis',
                ],
                [
                    'text' => 'Pasien',
                    'icon'    => 'fas fa-user-injured',
                    'url'  => 'pasien',
                    'shift'   => 'ml-2',
                    'active'  => ['pasien', 'pasien/create', 'regex:@^pasien(\/[0-9]+)?+$@', 'regex:@^pasien(\/[0-9]+)?\/edit+$@',],
                    'can' => 'rekam-medis',
                ],
                [
                    'text' => 'Demografi Pasien',
                    'icon'    => 'fas fa-user-injured',
                    'url'  => 'pasien_daerah',
                    'shift'   => 'ml-2',
                    'can' => 'rekam-medis',
                ],
                [
                    'text' => 'Laporan Index',
                    'icon'    => 'fas fa-chart-bar',
                    'shift'   => 'ml-2',
                    'can' => 'rekam-medis',
                    'submenu' => [
                        [
                            'text' => 'Index Penyakit Rawat Jalan',
                            'icon'    => 'fas fa-disease',
                            'url'  => 'index_penyakit_rajal',
                            'shift'   => 'ml-3',
                            'can' => 'rekam-medis',
                        ],
                    ]
                ],
                [
                    'text' => 'Diagnosa ICD-10',
                    'icon'    => 'fas fa-diagnoses',
                    'url'  => 'icd10',
                    'shift'   => 'ml-2',
                    'can' => 'rekam-medis',
                ],
                [
                    'text' => 'E-File Rekam Medis',
                    'icon'    => 'fas fa-diagnoses',
                    'shift'   => 'ml-2',
                    'can' => 'rekam-medis',
                    'url'  => 'efilerm',
                    // 'active'  => ['efilerm', 'efilerm/create' ,'regex:@^antrian/poliklinik(\/[0-9]+)?+$@', 'regex:@^antrian/poliklinik(\/[0-9]+)?\/edit+$@',  'antrian/poliklinik/create'],
                    'active'  => ['efilerm', 'efilerm/create'],

                ],
                [
                    'text' => 'Tindankan Prosedur',
                    'icon'    => 'fas fa-user-injured',
                    'url'  => 'tindakan',
                    'shift'   => 'ml-2',
                    'can' => 'rekam-medis',
                ],
            ],
        ],
        // KPO ELEKTRONIK
        [
            'text' => 'KPO Elektronik',
            'icon'    => 'fas fa-prescription-bottle-alt',
            'can' => 'rekam-medis',
            'submenu' => [
                [
                    'text' => 'Aplikasi KPO',
                    'icon'    => 'fas fa-pills',
                    'url'  => 'kpo',
                    'shift'   => 'ml-2',
                    'can' => 'rekam-medis',
                ],
                [
                    'text' => 'Obat',
                    'icon'    => 'fas fa-pills',
                    'url'  => 'obat',
                    'shift'   => 'ml-2',
                    'can' => 'rekam-medis',
                ],
            ],
        ],
        // USER ACCESS CONTROLL
        [
            'text'    => 'User Access Control',
            'icon'    => 'fas fa-users-cog',
            'can' => 'admin',
            'submenu' => [
                [
                    'text' => 'User',
                    'icon'    => 'fas fa-users',
                    'url'  => 'admin/user',
                    'shift'   => 'ml-2',
                    'can' => 'admin',
                    'active'  => ['admin/user', 'admin/user/create', 'regex:@^admin/user(\/[0-9]+)?+$@', 'regex:@^admin/user(\/[0-9]+)?\/edit+$@',],
                ],
                [
                    'text' => 'Role & Permission',
                    'icon'    => 'fas fa-user-shield',
                    'url'  => 'admin/role',
                    'shift'   => 'ml-2',
                    'active'  => ['admin/role', 'admin/role/create', 'regex:@^admin/role(\/[0-9]+)?+$@', 'regex:@^admin/role(\/[0-9]+)?\/edit+$@', 'regex:@^admin/permission(\/[0-9]+)?\/edit+$@'],
                    'can' => 'admin',
                ],
            ],
        ],
        [
            'text' => 'profile',
            'url'  => 'profile',
            'icon' => 'fas fa-fw fa-user',
        ],
        [
            'text'        => 'Status Bridging BPJS',
            'url'         => 'status',
            'icon'        => 'fas fa-info-circle',
            'can' => 'admin',
        ],
        [
            'text'        => 'Log Viewer',
            'url'         => 'log-viewer',
            'icon'        => 'fas fa-info-circle',
            'can' => 'admin',
        ],
        // ['header' => 'account_settings'],

        // [
        //     'text' => 'change_password',
        //     'url'  => 'password/reset',
        //     'icon' => 'fas fa-fw fa-lock',
        // ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Menu Filters
    |--------------------------------------------------------------------------
    |
    | Here we can modify the menu filters of the admin panel.
    |
    | For detailed instructions you can look the menu filters section here:
    | https://github.com/jeroennoten/Laravel-AdminLTE/wiki/Menu-Configuration
    |
    */

    'filters' => [
        JeroenNoten\LaravelAdminLte\Menu\Filters\GateFilter::class,
        JeroenNoten\LaravelAdminLte\Menu\Filters\HrefFilter::class,
        JeroenNoten\LaravelAdminLte\Menu\Filters\SearchFilter::class,
        JeroenNoten\LaravelAdminLte\Menu\Filters\ActiveFilter::class,
        JeroenNoten\LaravelAdminLte\Menu\Filters\ClassesFilter::class,
        JeroenNoten\LaravelAdminLte\Menu\Filters\LangFilter::class,
        JeroenNoten\LaravelAdminLte\Menu\Filters\DataFilter::class,
    ],

    /*
    |--------------------------------------------------------------------------
    | Plugins Initialization
    |--------------------------------------------------------------------------
    |
    | Here we can modify the plugins used inside the admin panel.
    |
    | For detailed instructions you can look the plugins section here:
    | https://github.com/jeroennoten/Laravel-AdminLTE/wiki/Plugins-Configuration
    |
    */

    'plugins' => [
        'TempusDominusBs4' => [
            'active' => false,
            'files' => [
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/moment/moment.min.js',
                ],
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/tempusdominus-bootstrap-4/js/tempusdominus-bootstrap-4.min.js',
                ],
                [
                    'type' => 'css',
                    'asset' => true,
                    'location' => 'vendor/tempusdominus-bootstrap-4/css/tempusdominus-bootstrap-4.min.css',
                ],
            ],
        ],
        'Datatables' => [
            'active' => false,
            'files' => [
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/datatables/js/jquery.dataTables.min.js',
                ],
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/datatables/js/dataTables.bootstrap4.min.js',
                ],
                [
                    'type' => 'css',
                    'asset' => true,
                    'location' => 'vendor/datatables/css/dataTables.bootstrap4.min.css',
                ],
            ],
        ],
        'DatatablesPlugins' => [
            'active' => false,
            'files' => [
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/datatables-plugins/buttons/js/dataTables.buttons.min.js',
                ],
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/datatables-plugins/buttons/js/buttons.bootstrap4.min.js',
                ],
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/datatables-plugins/buttons/js/buttons.html5.min.js',
                ],
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/datatables-plugins/buttons/js/buttons.print.min.js',
                ],
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/datatables-plugins/jszip/jszip.min.js',
                ],
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/datatables-plugins/pdfmake/pdfmake.min.js',
                ],
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/datatables-plugins/pdfmake/vfs_fonts.js',
                ],
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/datatables-plugins/buttons/js/buttons.colVis.min.js',
                ],
                [
                    'type' => 'css',
                    'asset' => true,
                    'location' => 'vendor/datatables-plugins/buttons/css/buttons.bootstrap4.min.css',
                ],
            ],
        ],
        'Select2' => [
            'active' => false,
            'files' => [
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/select2/js/select2.full.min.js',
                ],
                [
                    'type' => 'css',
                    'asset' => true,
                    'location' => 'vendor/select2/css/select2.min.css',
                ],
                [
                    'type' => 'css',
                    'asset' => true,
                    'location' => 'vendor/select2-bootstrap4-theme/select2-bootstrap4.min.css',
                ],
            ],
        ],
        'Chartjs' => [
            'active' => false,
            'files' => [
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/chart.js/Chart.min.js',
                ],
                [
                    'type' => 'css',
                    'asset' => true,
                    'location' => 'vendor/chart.js/Chart.min.css',
                ],
            ],
        ],
        'Sweetalert2' => [
            'active' => false,
            'files' => [
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/sweetalert2/sweetalert2.all.min.js',
                ],
                [
                    'type' => 'css',
                    'asset' => true,
                    'location' => 'vendor/sweetalert2-theme-bootstrap-4/bootstrap-4.min.css',
                ],
            ],
        ],
        'BootstrapSwitch' => [
            'active' => false,
            'files' => [
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/bootstrap-switch/js/bootstrap-switch.min.js',
                ],
            ],
        ],
        'Pace' => [
            'active' => true,
            'files' => [
                [
                    'type' => 'css',
                    'asset' => true,
                    'location' => 'vendor/pace-progress/themes/blue/pace-theme-flat-top.css'
                ],
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/pace-progress/pace.min.js'
                ],
            ],
        ],
        'DateRangePicker' => [
            'active' => false,
            'files' => [
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' =>  'vendor/moment/moment.min.js',
                ],
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' => 'vendor/daterangepicker/daterangepicker.js',
                ],
                [
                    'type' => 'css',
                    'asset' => true,
                    'location' => 'vendor/daterangepicker/daterangepicker.css',
                ],
            ],
        ],
        'EkkoLightBox' => [
            'active' => false,
            'files' => [
                [
                    'type' => 'js',
                    'asset' => true,
                    'location' =>  'vendor/ekko-lightbox/ekko-lightbox.min.js',
                ],
                [
                    'type' => 'css',
                    'asset' => true,
                    'location' =>  'vendor/ekko-lightbox/ekko-lightbox.css',
                ],
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | IFrame
    |--------------------------------------------------------------------------
    |
    | Here we change the IFrame mode configuration. Note these changes will
    | only apply to the view that extends and enable the IFrame mode.
    |
    | For detailed instructions you can look the iframe mode section here:
    | https://github.com/jeroennoten/Laravel-AdminLTE/wiki/IFrame-Mode-Configuration
    |
    */

    'iframe' => [
        'default_tab' => [
            'url' => null,
            'title' => null,
        ],
        'buttons' => [
            'close' => true,
            'close_all' => true,
            'close_all_other' => true,
            'scroll_left' => true,
            'scroll_right' => true,
            'fullscreen' => true,
        ],
        'options' => [
            'loading_screen' => 1000,
            'auto_show_new_tab' => true,
            'use_navbar_items' => true,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Livewire
    |--------------------------------------------------------------------------
    |
    | Here we can enable the Livewire support.
    |
    | For detailed instructions you can look the livewire here:
    | https://github.com/jeroennoten/Laravel-AdminLTE/wiki/Other-Configuration
    |
    */

    'livewire' => false,
];
