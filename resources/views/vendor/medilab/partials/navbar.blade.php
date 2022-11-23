<div id="topbar" class="d-flex align-items-center fixed-top">
    <div class="container d-flex justify-content-between">
        <div class="contact-info d-flex align-items-center">
            <i class="bi bi-envelope"></i> <a href="mailto:contact@example.com">brsud.waled@gmai.com</a>
            <i class="bi bi-phone"></i>0898 3311 118
        </div>
        <div class="d-none d-lg-flex social-links align-items-center">
            <a href="#" class="facebook"><i class="bi bi-whatsapp"></i></a>
            <a href="#" class="instagram"><i class="bi bi-instagram"></i></a>
            <a href="#" class="youtube"><i class="bi bi-youtube"></i></i></a>
        </div>
    </div>
</div>
<header id="header" class="fixed-top">
    <div class="container d-flex align-items-center">
        <h1 class="logo me-auto">
            <a href="index.html">
                <img src="{{ asset('assets/img/logo rs waled ico.png') }}" alt="" class="img-fluid">
                RSUD Waled</a>
        </h1>
        <nav id="navbar" class="navbar order-last order-lg-0">
            <ul>
                <li><a class="nav-link scrollto active" href="{{ route('landingpage') }}">Home</a></li>
                <li><a class="nav-link scrollto" href="#about">Pelayanan</a></li>
                <li><a class="nav-link scrollto" href="#services">Jadwal</a></li>
                <li><a class="nav-link scrollto" href="#departments">Antrian</a></li>
                <li><a class="nav-link scrollto" href="{{ route('bukutamu') }}#bukutamu">Buku Tamu</a></li>
                <li><a class="nav-link scrollto" href="#doctors">Bed Monitoring</a></li>
                <li><a class="nav-link scrollto" href="#contact">Kontak</a></li>
            </ul>
            <i class="bi bi-list mobile-nav-toggle"></i>
        </nav>
        <a href="#appointment" class="appointment-btn scrollto"><span class="d-none d-md-inline">Daftar Online</a>
    </div>
</header>
<section id="hero" class="d-flex align-items-center">
    <div class="container">
        <h1>SIMRS Waled</h1>
        <h2>Sistem Informasi Management Rumah Sakit Umum Daerah Waled</h2>
        <a href="#about" class="btn-get-started scrollto">Daftar Online</a>
    </div>
</section>