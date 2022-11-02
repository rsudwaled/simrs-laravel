@extends('adminlte::page')

@section('title', 'Daftar Pasien Baru')

@section('content_header')
    <h1>Daftar Pasien Baru</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-12">
            @if ($errors->any())
                <x-adminlte-alert title="Ops Terjadi Masalah !" theme="danger" dismissable>
                    <ul>
                        @foreach ($errors->all() as $error)
                            <li>{{ $error }}</li>
                        @endforeach
                    </ul>
                </x-adminlte-alert>
            @endif
            <form action="{{ route('api.ambil_antrean') }}" id="formDaftarPasien" method="post">
                @csrf
                <x-adminlte-card title="Jadwal Dokter Poliklinik Rawat Jalan" theme="warning" collapsible>
                    @php
                        $config = [
                            'format' => 'YYYY-MM-DD',
                            'dayViewHeaderFormat' => 'MMM YYYY',
                            'minDate' => "js:moment().add(-1, 'days')",
                            'maxDate' => "js:moment().add(6, 'days')",
                            'daysOfWeekDisabled' => [0],
                        ];
                    @endphp
                    <x-adminlte-input-date name="tanggalperiksa" label="Tanggal Periksa" :config="$config"
                        placeholder="Pilih Tanggal Surat Kontrol ..." value="{{ Carbon\Carbon::now()->format('Y-m-d') }}">
                        <x-slot name="prependSlot">
                            <div class="input-group-text bg-primary">
                                <i class="fas fa-calendar-alt"></i>
                            </div>
                        </x-slot>
                    </x-adminlte-input-date>
                    <x-adminlte-select2 name="pilihkodepoli" id="pilihkodepoli" label="Poliklinik">
                        <option value="0" selected>PILIH POLIKLINIK</option>
                        @foreach ($poli as $item)
                            <option value="{{ $item->kodesubspesialis }}">
                                {{ $item->kodesubspesialis }}
                                -
                                {{ $item->namasubspesialis }}
                            </option>
                        @endforeach
                    </x-adminlte-select2>
                    <input type="hidden" name="kodepoli" id="kodepoli">
                    <x-adminlte-select fgroup-class="kodedokter" name="kodedokter" id="kodedokter" label="Dokter" />
                    <x-slot name="footerSlot">
                        <x-adminlte-button icon="fas fa-sync" id="reset_jadwal" theme="danger" label="Reset Jadwal" />
                    </x-slot>
                </x-adminlte-card>
                <x-adminlte-card title="Data Pasien Rawat Jalan" class="datapasien" theme="warning" collapsible>
                    <x-adminlte-select name="pilihjeniskunjungan" id="pilihjeniskunjungan" label="Jenis Kunjungan Pasien">
                        <option value="0" selected>PILIH JENIS KUNJUNGAN PASIEN</option>
                        <option value="1">BPJS Rujukan Faskes 1</option>
                        <option value="2">BPJS Rujukan Internal</option>
                        <option value="3">BPJS Surat Kontrol</option>
                        <option value="4">BPJS Rujukan Antar RS</option>
                        <option value="5">UMUM (NON-JKN)</option>
                    </x-adminlte-select>
                    <input type="hidden" name="jeniskunjungan" id="jeniskunjungan">
                    <x-adminlte-input fgroup-class="nama" name="nama" label="Nama Pasien" />
                    <x-adminlte-input fgroup-class="norm" name="norm" label="Nomor Rekam Medis Pasien" />
                    <x-adminlte-input fgroup-class="nomorkartu" name="nomorkartu" label="No Kartu BPJS" type="number">
                        <x-slot name="appendSlot">
                            <x-adminlte-button name="btn_check_nomorkartu" id="btn_check_nomorkartu" theme="success"
                                label="Cek" />
                        </x-slot>
                    </x-adminlte-input>
                    <x-adminlte-input fgroup-class="nik" name="nik" label="NIK" type="number">
                        <x-slot name="appendSlot">
                            <x-adminlte-button name="btn_check_nik" id="btn_check_nik" theme="success" label="Cek" />
                        </x-slot>
                    </x-adminlte-input>
                    <x-adminlte-input fgroup-class="nohp" name="nohp" label="Nomor HP Pasien" />
                    <x-adminlte-select name="nomorreferensi" fgroup-class="nomorreferensi" label="Nomor Referensi">
                        <option value="0" selected>PILIH NOMOR REFERENSI</option>
                    </x-adminlte-select>
                    <x-slot name="footerSlot">
                        {{-- <x-adminlte-button icon="fas fa-user-md" id="daftar_pasien" theme="success" label="Daftar Pasien" /> --}}
                        <button type="submit" form="formDaftarPasien" value="Submit"
                            class="mr-auto btn btn-success withLoad">Buat Surat Kontrol</button>
                        <x-adminlte-button icon="fas fa-sync" id="reset" theme="danger" label="Reset Pasien" />
                    </x-slot>
                </x-adminlte-card>
            </form>
        </div>
    </div>
    {{-- <x-adminlte-modal id="modalCustom" title="Tambah Jadwal Libur" theme="success" v-centered static-backdrop>
        <form action="{{ route('jadwallibur.store') }}" id="myform" method="post">
            @csrf
            <x-adminlte-select2 name="kode_poli" label="Poliklinik">
                <option value="0">SEMUA POLIKLINIK</option>
                <x-adminlte-options :options=$polikliniks />
            </x-adminlte-select2>
            @php
                $config = [
                    'locale' => ['format' => 'YYYY/MM/DD'],
                ];
            @endphp
            <x-adminlte-date-range name="tanggal" label="Tanggal Libur" :config="$config" />
            <x-adminlte-textarea name="keterangan" placeholder="Masukan keterangan libur." label="Keterangan" />
        </form>
        <x-slot name="footerSlot">
            <x-adminlte-button theme="danger" label="Kembali" data-dismiss="modal" />
        </x-slot>
    </x-adminlte-modal> --}}
@stop
@section('plugins.Select2', true)
@section('plugins.TempusDominusBs4', true)

@section('js')
    <script src="{{ asset('vendor/sweetalert2/sweetalert2.all.min.js') }}"></script>
    <script>
        $(function() {
            $('.kodedokter').hide();
            $('.datapasien').hide();
            $('.nik').hide();
            $('.nomorkartu').hide();
            $('.nama').hide();
            $('.norm').hide();
            $('.nohp').hide();
            $('.nomorreferensi').hide();
            $('#pilihkodepoli').change(function() {
                var tanggalperiksa = $('#tanggalperiksa').val();
                var kodepoli = $('#pilihkodepoli').find('option:selected').val();
                $('#kodepoli').val(kodepoli);
                if (kodepoli != 0) {
                    var url =
                        "{{ route('antrian.index') }}" + "/console_jadwaldokter/" + kodepoli +
                        "/" + tanggalperiksa;
                    $.LoadingOverlay("show");
                    $.get(url, function(data) {
                        $('#kodedokter').find('option').remove();
                        $('.kodedokter').show();
                        if (data.length != 0) {
                            $('#kodedokter').append($(
                                "<option value='0'>PILIH DOKTER</option>"));
                            $.each(data, function(value) {
                                if (data[value].libur == "1") {
                                    var libur = "LIBUR " +
                                        data[value].jadwal;
                                    var disablee = "disabled";
                                } else {
                                    var libur = "" +
                                        data[value].jadwal;
                                    var disablee = "";
                                }
                                $('#kodedokter').append($(
                                    "<option value='" + data[value].kodedokter +
                                    "' " + disablee + " > " + libur +
                                    " " + data[value]
                                    .namadokter + "</option>"));
                                $.LoadingOverlay("hide", true);
                            });
                        } else {
                            $.LoadingOverlay("hide", true);
                            swal.fire(
                                'Error',
                                "Tidak Ada Jadwal Dokter Poliklinik " + kodepoli +
                                " di Tanggal " +
                                tanggalperiksa,
                                'error'
                            );
                        }
                    }).fail(function(error) {
                        alert(error);
                    });
                } else {
                    $('#kodedokter').find('option').remove();
                    $('.kodedokter').hide();
                }
            });
            $('#kodedokter').change(function() {
                var tanggalperiksa = $('#tanggalperiksa').val();
                var kodepoli = $('#kodepoli').val();
                $('#pilihkodepoli').prop('disabled', 'disabled');
                var kodedokter = $('#kodedokter').find('option:selected').val();
                if (kodedokter != 0) {
                    var url = "{{ route('api.status_antrean') }}";
                    var formData = {
                        tanggalperiksa: tanggalperiksa,
                        kodepoli: kodepoli,
                        kodedokter: kodedokter,
                    };
                    $.LoadingOverlay("show");
                    $.get(url, formData, function(data) {
                        $.LoadingOverlay("hide");
                        if (data.metadata.code == 200) {
                            if (data.response.sisaantrean <= 0) {
                                $.LoadingOverlay("hide");
                                $('.datapasien').hide();
                                swal.fire(
                                    'Error',
                                    "Mohon maaf kuota jadwal dokter sudah penuh",
                                    'error'
                                );
                            } else {
                                $.LoadingOverlay("hide");
                                $('.datapasien').show();
                                swal.fire(
                                    'Success',
                                    "Dokter " + kodedokter + " telah dipilih. Sisa kuota " +
                                    data
                                    .response
                                    .sisaantrean + " pasien.",
                                    'success'
                                );
                            }

                        } else {
                            $.LoadingOverlay("hide");
                            swal.fire(
                                'Error',
                                data.metadata.message,
                                'error'
                            );
                        }
                    }).fail(function(error) {
                        alert(error);
                    });
                } else {
                    $('.datapasien').hide();
                }
            });
            $('#pilihjeniskunjungan').change(function() {
                var jeniskunjungan = $('#pilihjeniskunjungan').find('option:selected').val();
                $('#jeniskunjungan').val(jeniskunjungan);
                if (1 >= jeniskunjungan <= 4) {
                    $('.nik').hide();
                    $('.nomorkartu').show();
                }
                if (jeniskunjungan == 5) {
                    $('.nik').show();
                    $('.nomorkartu').hide();
                }
                if (jeniskunjungan == 0) {
                    $('.nik').hide();
                    $('.nomorkartu').hide();
                }
            });
            $('#btn_check_nomorkartu').click(function() {
                var nomorkartu = $('#nomorkartu').val();
                var jeniskunjungan = $('#jeniskunjungan').val();
                var tanggalperiksa = $('#tanggalperiksa').val();
                $('#pilihjeniskunjungan').prop('disabled', 'disabled');
                var url = "{{ route('api.cek_nomorkartu') }}";
                $.LoadingOverlay("show");
                var formData = {
                    nomorkartu: nomorkartu,
                };
                $.get(url, formData, function(data) {
                    if (data.metaData.code == 200) {
                        $('#nik').val(data.response.peserta
                            .nik).attr('readonly', true);
                        $('#nama').val(data.response.peserta
                            .nama).attr('readonly', true);
                        $('#norm').val(data.response.peserta
                            .mr.noMR).attr('readonly', true);
                        $('#nohp').val(data.response.peserta
                            .mr.noTelepon);
                        $('#nomorkartu').attr('readonly', true);
                        $('.nik').show();
                        $('.nama').show();
                        $('.norm').show();
                        $('.nohp').show();
                        if (jeniskunjungan == 1) {
                            var url = "{{ route('api.rujukan_peserta') }}";
                            var formData = {
                                nomorkartu: nomorkartu,
                            };
                            $('#nomorreferensi').find('option')
                                .remove();
                            $('#nomorreferensi').append($(
                                "<option value='0' selected>PILIH NOMOR REFERENSI</option>"
                            ));
                            $.get(url, formData, function(rujukan) {
                                if (rujukan.metaData.code == 200) {
                                    $.each(rujukan.response.rujukan, function(value) {
                                        var tanggalkunjungan = rujukan.response
                                            .rujukan[value].tglKunjungan;
                                        var date3bulan = moment(tanggalkunjungan,
                                                "YYYY-MM-DD").add(3, 'months')
                                            .format('YYYY-MM-DD');
                                        var today = moment().format('YYYY-MM-DD');
                                        if (date3bulan > today) {
                                            var time = "";
                                            var disablee = "";
                                        } else {
                                            var time = "EXPIRED ";
                                            var disablee = "disabled";
                                        }
                                        $('#nomorreferensi').append($(
                                            "<option value='" + rujukan
                                            .response.rujukan[
                                                value].noKunjungan + "' " +
                                            disablee + " >" + time +
                                            rujukan
                                            .response.rujukan[
                                                value].noKunjungan + " " +
                                            rujukan
                                            .response.rujukan[
                                                value].pelayanan.nama +
                                            " POLI " +
                                            rujukan
                                            .response.rujukan[
                                                value].poliRujukan.nama +
                                            "</option>"
                                        ));
                                    });
                                    $('.nomorreferensi').show();
                                    $.LoadingOverlay("hide");
                                    swal.fire(
                                        'Success',
                                        "Nomor Kartu " + nomorkartu + " Atas Nama " +
                                        data
                                        .response.peserta.nama +
                                        " Data Rujukan Ditemukan",
                                        'success'
                                    );
                                } else {
                                    $.LoadingOverlay("hide");
                                    swal.fire(
                                        'Error',
                                        data.metaData.message,
                                        'error'
                                    );
                                }
                            }).fail(function(error) {
                                alert(error);
                            });
                        }
                        if (jeniskunjungan == 2) {
                            alert('2')
                            $.LoadingOverlay("hide");
                        }
                        if (jeniskunjungan == 3) {
                            var url = "{{ route('api.surat_kontrol_peserta') }}";
                            var formData = {
                                nomorkartu: nomorkartu,
                                tanggalperiksa: tanggalperiksa,
                                formatfilter: 2,
                            };
                            $('#nomorreferensi').find('option')
                                .remove();
                            $('#nomorreferensi').append($(
                                "<option value='0' selected>PILIH NOMOR REFERENSI</option>"
                            ));
                            $.get(url, formData, function(suratkontrols) {
                                if (suratkontrols.metaData.code == 200) {
                                    $.each(suratkontrols.response.list, function(value) {
                                        console.log(suratkontrols);
                                        $('#nomorreferensi').append($(
                                            "<option value='" +
                                            suratkontrols
                                            .response.list[
                                                value].noSuratKontrol +
                                            "' >" +
                                            suratkontrols
                                            .response.list[
                                                value].noSuratKontrol +
                                            " " +
                                            suratkontrols
                                            .response.list[
                                                value].tglRencanaKontrol +
                                            " POLI " +
                                            suratkontrols
                                            .response.list[
                                                value].namaPoliTujuan +
                                            " " + suratkontrols
                                            .response.list[
                                                value].namaDokter +
                                            "</option>"
                                        ));
                                    });
                                    $('.nomorreferensi').show();
                                    $.LoadingOverlay("hide");
                                    swal.fire(
                                        'Success',
                                        "Nomor Kartu " + nomorkartu + " Atas Nama " +
                                        data
                                        .response.peserta.nama +
                                        " Data Surat Kontrol Ditemukan",
                                        'success'
                                    );
                                } else {
                                    $('.nomorreferensi').hide();
                                    $.LoadingOverlay("hide");
                                    swal.fire(
                                        'Error (3)',
                                        suratkontrols.metaData.message,
                                        'error'
                                    );
                                }
                            }).fail(function(error) {
                                alert(error);
                            });
                        }
                        if (jeniskunjungan == 4) {
                            alert('4')
                            $.LoadingOverlay("hide");
                        }
                    } else {
                        $.LoadingOverlay("hide");
                        swal.fire(
                            'Error',
                            data.metaData.message,
                            'error'
                        );
                    }
                }).fail(function(error) {
                    alert(error);
                });
            });
            $('#btn_check_nik').click(function() {
                var nik = $('#nik').val();
                var url = "{{ route('api.cek_nik') }}";
                $('#pilihjeniskunjungan').prop('disabled', 'disabled');
                $.LoadingOverlay("show");
                var formData = {
                    nik: nik,
                };
                $.get(url, formData, function(data) {
                    if (data.metaData.code == 200) {
                        $('#nik').val(data.response.peserta
                            .nik).attr('readonly', true);
                        $('#nama').val(data.response.peserta
                            .nama).attr('readonly', true);
                        $('#norm').val(data.response.peserta
                            .mr.noMR).attr('readonly', true);
                        $('#nohp').val(data.response.peserta
                            .mr.noTelepon);
                        $('#nomorkartu').val(data.response.peserta
                            .noKartu).attr('readonly', true);
                        $('.nomorkartu').show();
                        $('.nik').show();
                        $('.nama').show();
                        $('.norm').show();
                        $('.nohp').show();
                        $.LoadingOverlay("hide");
                        swal.fire(
                            'Success',
                            "Nomor NIK/KTP " + nik + " atas nama " + data.response.peserta
                            .nama,
                            'success'
                        );
                    } else {
                        $.LoadingOverlay("hide");
                        swal.fire(
                            'Error',
                            data.metaData.message,
                            'error'
                        );

                    }
                }).fail(function(error) {
                    alert(error);
                });
            });
            $('#nomorreferensi').change(function() {
                var nomorreferensi = $('#nomorreferensi').find('option:selected').val();
                var kodedokter = $('#kodedokter').find('option:selected').val();
                var kodepoli = $('#kodepoli').val();
                var tanggalperiksa = $('#tanggalperiksa').val();
                var jeniskunjungan = $('#jeniskunjungan').val();
                if (nomorreferensi != 0) {
                    if (jeniskunjungan == 1) {
                        var formData = {
                            nomorreferensi: nomorreferensi,
                            jenisrujukan: 1,
                        }
                        $.LoadingOverlay("show");
                        var url = "{{ route('api.rujukan_nomor') }}";
                        $.get(url, formData, function(data) {
                            if (data.metaData.code == 200) {
                                if (data.response.rujukan.poliRujukan.kode == kodepoli) {
                                    var url = "{{ route('api.rujukan_jumlah_sep') }}";
                                    $.get(url, formData, function(data) {
                                        if (data.metaData.code == 200) {
                                            if (data.response.jumlahSEP == 0) {
                                                $.LoadingOverlay("hide");
                                                swal.fire(
                                                    'Success',
                                                    data.metaData.message,
                                                    'success'
                                                );
                                            } else {
                                                $.LoadingOverlay("hide");
                                                swal.fire({
                                                    icon: 'error',
                                                    title: 'Error!',
                                                    text: "Nomor Rujukan " +
                                                        nomorreferensi +
                                                        " anda telah digunakan untuk kunjungan pertama, silahkan klik 'Reset' dan pilih jenis kunjungan lainnya.",
                                                    allowOutsideClick: false,
                                                    allowEscapeKey: false
                                                });
                                            }
                                        } else {
                                            $.LoadingOverlay("hide");
                                            swal.fire(
                                                'Error',
                                                data.metaData.message,
                                                'error'
                                            );
                                        }
                                    }).fail(function(error) {
                                        alert(error);
                                    });
                                } else {
                                    $.LoadingOverlay("hide");
                                    swal.fire({
                                        icon: 'error',
                                        title: 'Error!',
                                        text: "Tujuan Nomor Rujukan " + nomorreferensi +
                                            " ke POLI " + data.response.rujukan.poliRujukan
                                            .kode + " berbeda dengan POLI " + kodepoli +
                                            " tujuan anda.",
                                        allowOutsideClick: false,
                                        allowEscapeKey: false
                                    });
                                }
                            } else {
                                $.LoadingOverlay("hide");
                                swal.fire(
                                    'Error',
                                    data.metaData.message,
                                    'error'
                                );
                            }
                        }).fail(function(error) {
                            alert(error);
                        });
                    }
                    if (jeniskunjungan == 3) {
                        var formData = {
                            nomorreferensi: nomorreferensi,
                        }
                        $.LoadingOverlay("show");
                        var url = "{{ route('api.surat_kontrol_nomor') }}";
                        $.get(url, formData, function(data) {
                            console.log(data);
                            if (data.metaData.code == 200) {
                                if (data.response.tglRencanaKontrol != tanggalperiksa) {
                                    console.log('tanggal periksa berbeda');
                                    $.LoadingOverlay("hide");
                                    swal.fire(
                                        'Error',
                                        "Maaf tanggal periksa (" + tanggalperiksa +
                                        ") anda berbeda dengan tanggal periksa yang terdaftar di Surat Kontrol (" +
                                        data.response.tglRencanaKontrol +
                                        "). Silahkan 'Reset Jadwal' pilihan jadwal anda sesuaikan dengan surat kontrol.",
                                        'error'
                                    );
                                } else if (data.response.poliTujuan != kodepoli) {
                                    console.log('poli berbeda');
                                    $.LoadingOverlay("hide");
                                    swal.fire(
                                        'Error',
                                        "Maaf poli tujuan (" + kodepoli +
                                        ") anda berbeda dengan poli tujuan yang terdaftar di Surat Kontrol (" +
                                        data.response.poliTujuan +
                                        "). Silahkan 'Reset Jadwal' pilihan jadwal anda sesuaikan dengan surat kontrol.",
                                        'error'
                                    );
                                } else if (data.response.kodeDokter != kodedokter) {
                                    console.log('dokter berbeda');
                                    $.LoadingOverlay("hide");
                                    swal.fire(
                                        'Error',
                                        "Maaf dokter tujuan (" + kodedokter +
                                        ") anda berbeda dengan dokter tujuan yang terdaftar di Surat Kontrol (" +
                                        data.response.kodeDokter +
                                        "). Silahkan 'Reset Jadwal' pilihan jadwal anda sesuaikan dengan surat kontrol.",
                                        'error'
                                    );
                                } else {
                                    $.LoadingOverlay("hide");
                                    swal.fire(
                                        'Success',
                                        data.metaData.message,
                                        'success'
                                    );
                                }
                            } else {
                                $.LoadingOverlay("hide");
                                swal.fire(
                                    'Error',
                                    data.metaData.message,
                                    'error'
                                );
                            }
                        }).fail(function(error) {
                            alert(error);
                        });
                    }
                }
            });
            $('#reset').click(function() {
                $('.nik').hide();
                $('.nomorkartu').hide();
                $('.nama').hide();
                $('.norm').hide();
                $('.nohp').hide();
                $('.nomorreferensi').hide();
                $('#nama').val('');
                $('#norm').val('');
                $('#nohp').val('');
                $('#nik').val('').attr('readonly', false);
                $('#nomorkartu').val('').attr('readonly', false);
                $('#nomorreferensi').val(0).change();
                $('#pilihjeniskunjungan').prop('disabled', false).val(0).change();
            });
            $('#reset_jadwal').click(function() {
                $('.nik').hide();
                $('.nomorkartu').hide();
                $('.nama').hide();
                $('.norm').hide();
                $('.nohp').hide();
                $('.datapasien').hide();
                $('.kodedokter').hide();
                $('.nomorreferensi').hide();
                $('#nama').val('');
                $('#norm').val('');
                $('#nohp').val('');
                $('#nik').val('').attr('readonly', false);
                $('#nomorkartu').val('').attr('readonly', false);
                $('#nomorreferensi').val(0).change();
                $('#kodedokter').find('option').remove();
                $('#kodepoli').val(0).change();
                $('#pilihjeniskunjungan').prop('disabled', false).val(0).change();
                $('#pilihkodepoli').prop('disabled', false).val(0).change();
            });
        });
    </script>
@endsection
