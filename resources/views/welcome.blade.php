<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <meta content="width=device-width, initial-scale=1.0" name="viewport">

    <title>SIM RSUD Waled</title>
    <meta content="" name="description">
    <meta content="" name="keywords">

    <!-- Favicons -->
    <link href="{{ asset('assets/img/logo rs waled ico.png') }}" rel="icon">
    <link href="{{ asset('assets/img/logo rs waled ico.png') }}" rel="apple-touch-icon">

    <!-- Vendor CSS Files -->
    <link href="{{ asset('assets/vendor/animate.css/animate.min.css') }}" rel="stylesheet">
    <link href="{{ asset('assets/vendor/bootstrap/css/bootstrap.min.css') }}" rel="stylesheet">
    <link href="{{ asset('assets/vendor/bootstrap-icons/bootstrap-icons.css') }}" rel="stylesheet">
    <link href="{{ asset('assets/vendor/boxicons/css/boxicons.min.css') }}" rel="stylesheet">
    <link href="{{ asset('assets/vendor/fontawesome-free/css/all.min.css') }}" rel="stylesheet">
    <link href="{{ asset('assets/vendor/glightbox/css/glightbox.min.css') }}" rel="stylesheet">
    <link href="{{ asset('assets/vendor/remixicon/remixicon.css') }}" rel="stylesheet">
    <link href="{{ asset('assets/vendor/swiper/swiper-bundle.min.css') }}" rel="stylesheet">

    <!-- Template Main CSS File -->
    <link href="{{ asset('assets/css/style.css') }}" rel="stylesheet">

    <style>
        #hero {
            /* background-size: cover; */
            /* height: 75ex; */
            background: url("{{ asset('rs-bagus-min.png') }}") center no-repeat !important;
        }

        .about .video-box {
            /* background-size: cover; */
            /* height: 75ex; */
            background: url("{{ asset('rs-bagus-min.png') }}") no-repeat !important;
        }
    </style>
</head>

<body>
    <!-- ======= Top Bar ======= -->
    <div id="topbar" class="d-flex align-items-center fixed-top">
        <div class="container d-flex justify-content-between">
            <div class="contact-info d-flex align-items-center">
                <i class="bi bi-envelope"></i> <a href="mailto:contact@example.com">it.support@rsudwaled.id</a>
                <i class="bi bi-phone"></i> 0895 2990 9036
            </div>
            <div class="d-none d-lg-flex social-links align-items-center">
                <a href="#" class="twitter"><i class="bi bi-twitter"></i></a>
                <a href="#" class="facebook"><i class="bi bi-facebook"></i></a>
                <a href="#" class="instagram"><i class="bi bi-instagram"></i></a>
                <a href="#" class="linkedin"><i class="bi bi-linkedin"></i></i></a>
            </div>
        </div>
    </div>
    <header id="header" class="fixed-top">
        <div class="container d-flex align-items-center">
            <a href="/" class="logo m-2"><img src="{{ asset('assets/img/logo rs waled ico.png') }}"
                    alt="" class="img-fluid"></a>
            <h1 class="logo me-auto"><a href="/">RSUD Waled</a></h1>
            <nav id="navbar" class="navbar order-last order-lg-0">
                <ul>
                    <li><a class="nav-link scrollto" href="{{ route('daftar_pasien') }}">Daftar Pasien</a></li>
                </ul>
                <i class="bi bi-list mobile-nav-toggle"></i>
            </nav>
            <a href="{{ route('login') }}" class="appointment-btn scrollto"><span class="d-none d-md-inline"></span>
                @guest
                    Login
                @else
                    Dashboard
                @endguest
            </a>
        </div>
    </header>
    <section id="hero" class="d-flex align-items-center">
        <div class="container">
            <h1>SIM RSUD Waled</h1>
            <h2>Sistem Informasi Management <br> Rumah Sakit Umum Daerah Waled</h2>
            {{-- <a href="{{route('pasien.create')}}" class="btn-get-started scrollto">Daftar Sebagai Pasien</a> --}}
        </div>
    </section><!-- End Hero -->
    <main id="main">
        <!-- ======= Why Us Section ======= -->
        <section id="why-us" class="why-us">
            <div class="container">
                <div class="row">
                    <div class="col-lg-4 d-flex align-items-stretch">
                        <div class="content">
                            <h3>Apa sih SIM RSUD Waled ?</h3>
                            <p>
                                SIMRS adalah suatu sistem teknologi informasi komunikasi yang
                                memproses dan mengintegrasikan seluruh alur proses pelayanan
                                Rumah Sakit dalam bentuk jaringan koordinasi, pelaporan dan
                                prosedur administrasi untuk memperoleh informasi secara tepat dan
                                akurat, dan merupakan bagian dari Sistem Informasi Kesehatan.
                            </p>
                            <div class="text-center">
                                <a href="{{ route('login') }}" class="more-btn">
                                    @guest
                                        Login
                                    @else
                                        Dashboard
                                    @endguest
                                    <i class="bx bx-chevron-right"></i>
                                </a>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-8 d-flex align-items-stretch">
                        <div class="icon-boxes d-flex flex-column justify-content-center">
                            <div class="row">
                                <div class="col-xl-4 d-flex align-items-stretch">
                                    <div class="icon-box mt-4 mt-xl-0">
                                        <i class="bx bx-message-add"></i>
                                        <h4>Information</h4>
                                        <p>Menyajikan Informasi yang dibutuhkan untuk Internal dan Eksternal Rumah Sakit
                                        </p>
                                    </div>
                                </div>
                                <div class="col-xl-4 d-flex align-items-stretch">
                                    <div class="icon-box mt-4 mt-xl-0">
                                        <i class="bx bx-clinic"></i>
                                        <h4>Service</h4>
                                        <p>Pelayanan Kesehatan berbasis Digital Untuk Rumah Sakit</p>
                                    </div>
                                </div>
                                <div class="col-xl-4 d-flex align-items-stretch">
                                    <div class="icon-box mt-4 mt-xl-0">
                                        <i class="bx bx-line-chart"></i>
                                        <h4>Controlling</h4>
                                        <p>Memudahkan proses Pelaporan, Pemantauan, Pengendalian dan Evaluasi Rumah
                                            Sakit</p>
                                    </div>
                                </div>
                            </div>
                        </div><!-- End .content-->
                    </div>
                </div>

            </div>
        </section>
        <!-- End Why Us Section -->
        <!-- ======= About Section ======= -->
        <section id="about" class="about">
            <div class="container-fluid">
                <div class="row">
                    <div
                        class="col-xl-5 col-lg-6 video-box d-flex justify-content-center align-items-stretch position-relative">
                        <a href="https://www.youtube.com/watch?v=oRj04KcUmuU" class="glightbox play-btn mb-4"></a>
                    </div>

                    <div
                        class="col-xl-7 col-lg-6 icon-boxes d-flex flex-column align-items-stretch justify-content-center py-5 px-lg-5">
                        <h3>Pelayanan Online Pasien SIMRS Waled</h3>
                        <p>Esse voluptas cumque vel exercitationem. Reiciendis est hic accusamus. Non ipsam et sed
                            minima temporibus laudantium. Soluta voluptate sed facere corporis dolores excepturi. Libero
                            laboriosam sint et id nulla tenetur. Suscipit aut voluptate.</p>
                        <div class="icon-box">
                            <div class="icon"><i class="bx bx-fingerprint"></i></div>
                            <h4 class="title"><a href=""> Jadwal Dokter & Libur Rawat Jalan</a></h4>
                            <p class="description">PERATURAN SISTEM INFORMASI MANAJEMEN RUMAH SAKIT</p>
                        </div>
                        <div class="icon-box">
                            <div class="icon"><i class="bx bx-fingerprint"></i></div>
                            <h4 class="title"><a href="">Antrian Online Rawat Jalan</a></h4>
                            <p class="description">PERATURAN SISTEM INFORMASI MANAJEMEN RUMAH SAKIT</p>
                        </div>
                        <div class="icon-box">
                            <div class="icon"><i class="bx bx-fingerprint"></i></div>
                            <h4 class="title"><a href="">Administrasi Online Pasien</a></h4>
                            <p class="description">PERATURAN SISTEM INFORMASI MANAJEMEN RUMAH SAKIT</p>
                        </div>
                        <div class="icon-box">
                            <div class="icon"><i class="bx bx-gift"></i></div>
                            <h4 class="title"><a href="">Bed Monitoring Rawat Inap</a></h4>
                            <p class="description">At vero eos et accusamus et iusto odio dignissimos ducimus qui
                                blanditiis praesentium voluptatum deleniti atque</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section id="faq" class="faq section-bg">
            <div class="container">
                <div class="section-title">
                    <h2>Jadwal Poliklinik Rawat Jalan</h2>
                    <p>Dokter sewaktu waktu dapat membatalkan jadwal praktek dikarenakan cuti atau berhalangan. Silahkan
                        tetap dapatkan informasi terbaru jadwal dokter di web kami. <br>Terima kasih dan harap
                        maklum. Update terakhir {{ \Carbon\Carbon::now() }}</p>
                </div>
                <div class="faq-list">
                    <ul>
                        <li data-aos="fade-up"> <i class="bx bx-help-circle icon-help"></i> <a
                                data-bs-toggle="collapse" class="collapse collapsed" data-bs-target="#faq-list-1"
                                aria-expanded="false">Senin <i class="bx bx-chevron-down icon-show"></i><i
                                    class="bx bx-chevron-up icon-close"></i></a>
                            <div id="faq-list-1" class="collapse" data-bs-parent=".faq-list" style="">
                                <p> Feugiat pretium nibh ipsum consequat. Tempus iaculis urna id volutpat lacus laoreet
                                    non curabitur gravida. Venenatis lectus magna fringilla urna porttitor rhoncus dolor
                                    purus non.</p>
                            </div>
                        </li>
                        <li data-aos="fade-up" data-aos-delay="100"> <i class="bx bx-help-circle icon-help"></i> <a
                                data-bs-toggle="collapse" data-bs-target="#faq-list-2" class="collapsed"
                                aria-expanded="false">Selasa<i class="bx bx-chevron-down icon-show"></i><i
                                    class="bx bx-chevron-up icon-close"></i></a>
                            <div id="faq-list-2" class="collapse" data-bs-parent=".faq-list" style="">
                                <p> Dolor sit amet consectetur adipiscing elit pellentesque habitant morbi. Id interdum
                                    velit laoreet id donec ultrices. Fringilla phasellus faucibus scelerisque eleifend
                                    donec pretium. Est pellentesque elit ullamcorper dignissim. Mauris ultrices eros in
                                    cursus turpis massa tincidunt dui.</p>
                            </div>
                        </li>
                        <li data-aos="fade-up" data-aos-delay="200"> <i class="bx bx-help-circle icon-help"></i> <a
                                data-bs-toggle="collapse" data-bs-target="#faq-list-3" class="collapsed"
                                aria-expanded="false">Rabu<i class="bx bx-chevron-down icon-show"></i><i
                                    class="bx bx-chevron-up icon-close"></i></a>
                            <div id="faq-list-3" class="collapse" data-bs-parent=".faq-list" style="">
                                <p> Eleifend mi in nulla posuere sollicitudin aliquam ultrices sagittis orci. Faucibus
                                    pulvinar elementum integer enim. Sem nulla pharetra diam sit amet nisl suscipit.
                                    Rutrum tellus pellentesque eu tincidunt. Lectus urna duis convallis convallis
                                    tellus. Urna molestie at elementum eu facilisis sed odio morbi quis</p>
                            </div>
                        </li>
                        <li data-aos="fade-up" data-aos-delay="300"> <i class="bx bx-help-circle icon-help"></i> <a
                                data-bs-toggle="collapse" data-bs-target="#faq-list-4" class="collapsed"
                                aria-expanded="false">Kamis
                                <i class="bx bx-chevron-down icon-show"></i><i
                                    class="bx bx-chevron-up icon-close"></i></a>
                            <div id="faq-list-4" class="collapse" data-bs-parent=".faq-list" style="">
                                <p> Molestie a iaculis at erat pellentesque adipiscing commodo. Dignissim suspendisse in
                                    est ante in. Nunc vel risus commodo viverra maecenas accumsan. Sit amet nisl
                                    suscipit adipiscing bibendum est. Purus gravida quis blandit turpis cursus in.</p>
                            </div>
                        </li>
                        <li data-aos="fade-up" data-aos-delay="400"> <i class="bx bx-help-circle icon-help"></i> <a
                                data-bs-toggle="collapse" data-bs-target="#faq-list-5" class="collapsed"
                                aria-expanded="false">Jumat<i class="bx bx-chevron-down icon-show"></i><i
                                    class="bx bx-chevron-up icon-close"></i></a>
                            <div id="faq-list-5" class="collapse" data-bs-parent=".faq-list">
                                <p> Laoreet sit amet cursus sit amet dictum sit amet justo. Mauris vitae ultricies leo
                                    integer malesuada nunc vel. Tincidunt eget nullam non nisi est sit amet. Turpis nunc
                                    eget lorem dolor sed. Ut venenatis tellus in metus vulputate eu scelerisque.</p>
                            </div>
                        </li>
                        <li data-aos="fade-up" data-aos-delay="500"> <i class="bx bx-help-circle icon-help"></i> <a
                                data-bs-toggle="collapse" data-bs-target="#faq-list-5" class="collapsed"
                                aria-expanded="false">Sabtu<i class="bx bx-chevron-down icon-show"></i><i
                                    class="bx bx-chevron-up icon-close"></i></a>
                            <div id="faq-list-5" class="collapse" data-bs-parent=".faq-list">
                                <p><b>Poliklinik Mata</b></p>
                                <p> Laoreet sit amet cursus sit amet dictum sit amet justo. Mauris vitae ultricies leo
                                    integer malesuada nunc vel. Tincidunt eget nullam non nisi est sit amet. Turpis nunc
                                    eget lorem dolor sed. Ut venenatis tellus in metus vulputate eu scelerisque.
                                </p>
                                <p><b>Poliklinik Mata</b></p>
                                <p> Laoreet sit amet cursus sit amet dictum sit amet justo. Mauris vitae ultricies leo
                                    integer malesuada nunc vel. Tincidunt eget nullam non nisi est sit amet. Turpis nunc
                                    eget lorem dolor sed. Ut venenatis tellus in metus vulputate eu scelerisque.
                                </p>
                                <p><b>Poliklinik Mata</b></p>
                                <p> Laoreet sit amet cursus sit amet dictum sit amet justo. Mauris vitae ultricies leo
                                    integer malesuada nunc vel. Tincidunt eget nullam non nisi est sit amet. Turpis nunc
                                    eget lorem dolor sed. Ut venenatis tellus in metus vulputate eu scelerisque.
                                </p>
                                <p><b>Poliklinik Mata</b></p>
                                <p> Laoreet sit amet cursus sit amet dictum sit amet justo. Mauris vitae ultricies leo
                                    integer malesuada nunc vel. Tincidunt eget nullam non nisi est sit amet. Turpis nunc
                                    eget lorem dolor sed. Ut venenatis tellus in metus vulputate eu scelerisque.
                                </p>
                                <p><b>Poliklinik Mata</b></p>
                                <p> Laoreet sit amet cursus sit amet dictum sit amet justo. Mauris vitae ultricies leo
                                    integer malesuada nunc vel. Tincidunt eget nullam non nisi est sit amet. Turpis nunc
                                    eget lorem dolor sed. Ut venenatis tellus in metus vulputate eu scelerisque.
                                </p>
                                <p><b>Poliklinik Mata</b></p>
                                <p> Laoreet sit amet cursus sit amet dictum sit amet justo. Mauris vitae ultricies leo
                                    integer malesuada nunc vel. Tincidunt eget nullam non nisi est sit amet. Turpis nunc
                                    eget lorem dolor sed. Ut venenatis tellus in metus vulputate eu scelerisque.
                                </p>
                                <p><b>Poliklinik Mata</b></p>
                                <p> Laoreet sit amet cursus sit amet dictum sit amet justo. Mauris vitae ultricies leo
                                    integer malesuada nunc vel. Tincidunt eget nullam non nisi est sit amet. Turpis nunc
                                    eget lorem dolor sed. Ut venenatis tellus in metus vulputate eu scelerisque.
                                </p>
                                <p><b>Poliklinik Mata</b></p>
                                <p> Laoreet sit amet cursus sit amet dictum sit amet justo. Mauris vitae ultricies leo
                                    integer malesuada nunc vel. Tincidunt eget nullam non nisi est sit amet. Turpis nunc
                                    eget lorem dolor sed. Ut venenatis tellus in metus vulputate eu scelerisque.
                                </p>
                                <p><b>Poliklinik Mata</b></p>
                                <p> Laoreet sit amet cursus sit amet dictum sit amet justo. Mauris vitae ultricies leo
                                    integer malesuada nunc vel. Tincidunt eget nullam non nisi est sit amet. Turpis nunc
                                    eget lorem dolor sed. Ut venenatis tellus in metus vulputate eu scelerisque.
                                </p>
                                <p><b>Poliklinik Mata</b></p>
                                <p> Laoreet sit amet cursus sit amet dictum sit amet justo. Mauris vitae ultricies leo
                                    integer malesuada nunc vel. Tincidunt eget nullam non nisi est sit amet. Turpis nunc
                                    eget lorem dolor sed. Ut venenatis tellus in metus vulputate eu scelerisque.
                                </p>
                                <p><b>Poliklinik Mata</b></p>
                                <p> Laoreet sit amet cursus sit amet dictum sit amet justo. Mauris vitae ultricies leo
                                    integer malesuada nunc vel. Tincidunt eget nullam non nisi est sit amet. Turpis nunc
                                    eget lorem dolor sed. Ut venenatis tellus in metus vulputate eu scelerisque.
                                </p>
                                <p><b>Poliklinik Mata</b></p>
                                <p> Laoreet sit amet cursus sit amet dictum sit amet justo. Mauris vitae ultricies leo
                                    integer malesuada nunc vel. Tincidunt eget nullam non nisi est sit amet. Turpis nunc
                                    eget lorem dolor sed. Ut venenatis tellus in metus vulputate eu scelerisque.
                                </p>
                                <p><b>Poliklinik Mata</b></p>
                                <p> Laoreet sit amet cursus sit amet dictum sit amet justo. Mauris vitae ultricies leo
                                    integer malesuada nunc vel. Tincidunt eget nullam non nisi est sit amet. Turpis nunc
                                    eget lorem dolor sed. Ut venenatis tellus in metus vulputate eu scelerisque.
                                </p>

                            </div>
                        </li>
                    </ul>
                </div>
            </div>
        </section>

        <section id="services" class="services">
            <div class="container">
                <div class="section-title">
                    <h2>Antrian Online Rawat Jalan</h2>
                    <p>Magnam dolores commodi suscipit. Necessitatibus eius consequatur ex aliquid fuga eum quidem. Sit
                        sint consectetur velit. Quisquam quos quisquam cupiditate. Et nemo qui impedit suscipit alias
                        ea. Quia fugiat sit in iste officiis commodi quidem hic quas.</p>
                </div>
                <div class="row">
                    <div class="col-lg-4 col-md-6 d-flex align-items-stretch">
                        <div class="icon-box">
                            <div class="icon"><i class="fas fa-heartbeat"></i></div>
                            <h4><a href="">Pasien BPJS</a></h4>
                            <p>Voluptatum deleniti atque corrupti quos dolores et quas molestias excepturi</p>
                        </div>
                    </div>
                    <div class="col-lg-4 col-md-6 d-flex align-items-stretch mt-4 mt-md-0">
                        <div class="icon-box">
                            <div class="icon"><i class="fas fa-pills"></i></div>
                            <h4><a href="">Pasien Umum</a></h4>
                            <p>Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore</p>
                        </div>
                    </div>
                    <div class="col-lg-4 col-md-6 d-flex align-items-stretch mt-4 mt-lg-0">
                        <div class="icon-box">
                            <div class="icon"><i class="fas fa-hospital-user"></i></div>
                            <h4><a href="">Pasien Asuransi Lainnya</a></h4>
                            <p>Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        <section id="counts" class="counts">
            <div class="container">
                <div class="row">
                    <div class="col-lg-3 col-md-6">
                        <div class="count-box">
                            <i class="fas fa-user-md"></i>
                            <span data-purecounter-start="0" data-purecounter-end="85" data-purecounter-duration="1"
                                class="purecounter"></span>
                            <p>Doctors</p>
                        </div>
                    </div>
                    <div class="col-lg-3 col-md-6 mt-5 mt-md-0">
                        <div class="count-box">
                            <i class="far fa-hospital"></i>
                            <span data-purecounter-start="0" data-purecounter-end="18" data-purecounter-duration="1"
                                class="purecounter"></span>
                            <p>Departments</p>
                        </div>
                    </div>
                    <div class="col-lg-3 col-md-6 mt-5 mt-lg-0">
                        <div class="count-box">
                            <i class="fas fa-flask"></i>
                            <span data-purecounter-start="0" data-purecounter-end="12" data-purecounter-duration="1"
                                class="purecounter"></span>
                            <p>Research Labs</p>
                        </div>
                    </div>
                    <div class="col-lg-3 col-md-6 mt-5 mt-lg-0">
                        <div class="count-box">
                            <i class="fas fa-award"></i>
                            <span data-purecounter-start="0" data-purecounter-end="150" data-purecounter-duration="1"
                                class="purecounter"></span>
                            <p>Awards</p>
                        </div>
                    </div>
                </div>
            </div>
        </section>
        <section id="departments" class="departments">
            <div class="container">
                <div class="section-title">
                    <h2>Bed Monitoring</h2>
                    <p>Magnam dolores commodi suscipit. Necessitatibus eius consequatur ex aliquid fuga eum quidem. Sit
                        sint consectetur velit. Quisquam quos quisquam cupiditate. Et nemo qui impedit suscipit alias
                        ea. Quia fugiat sit in iste officiis commodi quidem hic quas.</p>
                </div>
                <div class="row gy-4">
                    <div class="col-lg-3">
                        <ul class="nav nav-tabs flex-column" role="tablist">
                            <li class="nav-item" role="presentation"> <a class="nav-link show" data-bs-toggle="tab"
                                    href="#tab-1" aria-selected="false" role="tab" tabindex="-1">Senin</a>
                            </li>
                            <li class="nav-item" role="presentation"> <a class="nav-link active"
                                    data-bs-toggle="tab" href="#tab-2" aria-selected="true"
                                    role="tab">Selasa</a></li>
                            <li class="nav-item" role="presentation"> <a class="nav-link" data-bs-toggle="tab"
                                    href="#tab-3" aria-selected="false" role="tab" tabindex="-1">Rabu</a></li>
                            <li class="nav-item" role="presentation"> <a class="nav-link" data-bs-toggle="tab"
                                    href="#tab-4" aria-selected="false" role="tab" tabindex="-1">Kamis</a>
                            </li>
                            <li class="nav-item" role="presentation"> <a class="nav-link" data-bs-toggle="tab"
                                    href="#tab-5" aria-selected="false" role="tab" tabindex="-1">Jumat</a>
                            </li>
                            <li class="nav-item" role="presentation"> <a class="nav-link" data-bs-toggle="tab"
                                    href="#tab-5" aria-selected="false" role="tab" tabindex="-1">Sabtu</a>
                            </li>
                        </ul>
                    </div>
                    <div class="col-lg-9">
                        <div class="tab-content">
                            <div class="tab-pane" id="tab-1" role="tabpanel">
                                <div class="row gy-4">
                                    <div class="col-lg-8 details order-2 order-lg-1">
                                        <h5><b>Poliklinik Mata</b></h5>
                                        <p class="fst-italic">Qui laudantium consequatur laborum sit qui ad sapiente
                                            dila parde sonata raqer a videna mareta paulona marka</p>
                                        <p>Et nobis maiores eius. Voluptatibus ut enim blanditiis atque harum sint.
                                            Laborum eos ipsum ipsa odit magni. Incidunt hic ut molestiae aut qui. Est
                                            repellat minima eveniet eius et quis magni nihil. Consequatur dolorem
                                            quaerat quos qui similique accusamus nostrum rem vero</p>
                                    </div>
                                    <div class="col-lg-4 text-center order-1 order-lg-2"> <img
                                            src="assets/img/departments-1.jpg" alt="" class="img-fluid">
                                    </div>
                                </div>
                            </div>
                            <div class="tab-pane active show" id="tab-2" role="tabpanel">
                                <div class="row gy-4">
                                    <div class="col-lg-8 details order-2 order-lg-1">
                                        <p><b>Poliklinik Mata</b></p>
                                        <p>Ea ipsum voluptatem consequatur quis est. Illum error ullam omnis quia et
                                            reiciendis sunt sunt est. Non aliquid repellendus itaque accusamus eius et
                                            velit ipsa voluptates. Optio nesciunt eaque beatae accusamus lerode pakto
                                            madirna desera vafle de nideran pal</p>
                                    </div>
                                    <div class="col-lg-4 text-center order-1 order-lg-2"> <img
                                            src="assets/img/departments-2.jpg" alt="" class="img-fluid">
                                    </div>
                                </div>
                            </div>
                            <div class="tab-pane" id="tab-3" role="tabpanel">
                                <div class="row gy-4">
                                    <div class="col-lg-8 details order-2 order-lg-1">
                                        <h3>Impedit facilis occaecati odio neque aperiam sit</h3>
                                        <p class="fst-italic">Eos voluptatibus quo. Odio similique illum id quidem non
                                            enim fuga. Qui natus non sunt dicta dolor et. In asperiores velit quaerat
                                            perferendis aut</p>
                                        <p>Iure officiis odit rerum. Harum sequi eum illum corrupti culpa veritatis
                                            quisquam. Neque necessitatibus illo rerum eum ut. Commodi ipsam minima
                                            molestiae sed laboriosam a iste odio. Earum odit nesciunt fugiat sit ullam.
                                            Soluta et harum voluptatem optio quae</p>
                                    </div>
                                    <div class="col-lg-4 text-center order-1 order-lg-2"> <img
                                            src="assets/img/departments-3.jpg" alt="" class="img-fluid">
                                    </div>
                                </div>
                            </div>
                            <div class="tab-pane" id="tab-4" role="tabpanel">
                                <div class="row gy-4">
                                    <div class="col-lg-8 details order-2 order-lg-1">
                                        <h3>Fuga dolores inventore laboriosam ut est accusamus laboriosam dolore</h3>
                                        <p class="fst-italic">Totam aperiam accusamus. Repellat consequuntur iure
                                            voluptas iure porro quis delectus</p>
                                        <p>Eaque consequuntur consequuntur libero expedita in voluptas. Nostrum ipsam
                                            necessitatibus aliquam fugiat debitis quis velit. Eum ex maxime error in
                                            consequatur corporis atque. Eligendi asperiores sed qui veritatis aperiam
                                            quia a laborum inventore</p>
                                    </div>
                                    <div class="col-lg-4 text-center order-1 order-lg-2"> <img
                                            src="assets/img/departments-4.jpg" alt="" class="img-fluid">
                                    </div>
                                </div>
                            </div>
                            <div class="tab-pane" id="tab-5" role="tabpanel">
                                <div class="row gy-4">
                                    <div class="col-lg-8 details order-2 order-lg-1">
                                        <h3>Est eveniet ipsam sindera pad rone matrelat sando reda</h3>
                                        <p class="fst-italic">Omnis blanditiis saepe eos autem qui sunt debitis porro
                                            quia.</p>
                                        <p>Exercitationem nostrum omnis. Ut reiciendis repudiandae minus. Omnis
                                            recusandae ut non quam ut quod eius qui. Ipsum quia odit vero atque qui
                                            quibusdam amet. Occaecati sed est sint aut vitae molestiae voluptate vel</p>
                                    </div>
                                    <div class="col-lg-4 text-center order-1 order-lg-2"> <img
                                            src="assets/img/departments-5.jpg" alt="" class="img-fluid">
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </section>
    </main>
    <footer id="footer">
        <div class="footer-top">
            <div class="container">
                <div class="row">
                    <div class="col-lg-3 col-md-6 footer-contact">
                        <h3>RSUD Waled</h3>
                        <p>
                            Jl. Prabu Kiansantang No.4 <br>
                            Kecamatan Waled Kabupaten Cirebon<br>
                            Jawa Barat 45187 <br><br>
                            <strong>Phone:</strong> +1 5589 55488 55<br>
                            <strong>Email:</strong> info@example.com<br>
                        </p>
                    </div>
                    <div class="col-lg-2 col-md-6 footer-links">
                        <h4>Useful Links</h4>
                        <ul>
                            <li><i class="bx bx-chevron-right"></i> <a href="#">Home</a></li>
                            <li><i class="bx bx-chevron-right"></i> <a href="#">About us</a></li>
                            <li><i class="bx bx-chevron-right"></i> <a href="#">Services</a></li>
                            <li><i class="bx bx-chevron-right"></i> <a href="#">Terms of service</a></li>
                            <li><i class="bx bx-chevron-right"></i> <a href="#">Privacy policy</a></li>
                        </ul>
                    </div>
                    <div class="col-lg-3 col-md-6 footer-links">
                        <h4>Services Integration</h4>
                        <ul>
                            <li><i class="bx bx-chevron-right"></i> <a href="#">Vclaim & Antrian BPJS</a></li>
                            <li><i class="bx bx-chevron-right"></i> <a href="#">Satu Sehat Kemenkes</a></li>
                        </ul>
                    </div>
                    <div class="col-lg-4 col-md-6 footer-newsletter">
                        <h4>Join Our Newsletter</h4>
                        <p>Tamen quem nulla quae legam multos aute sint culpa legam noster magna</p>
                        <form action="" method="post">
                            <input type="email" name="email"><input type="submit" value="Subscribe">
                        </form>
                    </div>
                </div>
            </div>
        </div>
        <div class="container d-md-flex py-4">
            <div class="me-md-auto text-center text-md-start">
                <div class="copyright">
                    &copy; Copyright <strong><span>SIM RSUD Waled</span></strong>. All Rights Reserved
                </div>
                <div class="cblackits">
                    <!-- All the links in the footer should remain intact. -->
                    <!-- You can delete the links only if you purchased the pro version. -->
                    <!-- Licensing information: https://bootstrapmade.com/license/ -->
                    <!-- Purchase the pro version with working PHP/AJAX contact form: https://bootstrapmade.com/medilab-free-medical-bootstrap-theme/ -->
                    Designed by <a href="#">TIM IT RSUD Waled</a>
                </div>
            </div>
            <div class="social-links text-center text-md-right pt-3 pt-md-0">
                <a href="#" class="twitter"><i class="bx bxl-twitter"></i></a>
                <a href="#" class="facebook"><i class="bx bxl-facebook"></i></a>
                <a href="#" class="instagram"><i class="bx bxl-instagram"></i></a>
                <a href="#" class="google-plus"><i class="bx bxl-skype"></i></a>
                <a href="#" class="linkedin"><i class="bx bxl-linkedin"></i></a>
            </div>
        </div>
    </footer>
    <div id="preloader"></div>
    <a href="#" class="back-to-top d-flex align-items-center justify-content-center"><i
            class="bi bi-arrow-up-short"></i></a>
    <!-- Vendor JS Files -->
    <script src="{{ asset('assets/vendor/bootstrap/js/bootstrap.bundle.min.js') }}"></script>
    <script src="{{ asset('assets/vendor/glightbox/js/glightbox.min.js') }}"></script>
    <script src="{{ asset('assets/vendor/php-email-form/validate.js') }}"></script>
    <script src="{{ asset('assets/vendor/purecounter/purecounter.js') }}"></script>
    <script src="{{ asset('assets/vendor/swiper/swiper-bundle.min.js') }}"></script>
    <!-- Template Main JS File -->
    <script src="{{ asset('assets/js/main.js') }}"></script>
</body>

</html>
