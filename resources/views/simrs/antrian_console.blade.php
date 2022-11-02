@extends('adminlte::master')

@inject('layoutHelper', 'JeroenNoten\LaravelAdminLte\Helpers\LayoutHelper')

@section('title', 'Antrian QR Code')
@section('body')

    <div class="wrapper">
        <div class="row p-1">
            {{-- checkin --}}
            <div class="col-md-5">
                <x-adminlte-card title="Anjungan Checkin Antrian RSUD Waled" theme="primary" icon="fas fa-qrcode">
                    <div class="text-center">
                        <x-adminlte-input name="kodebooking" label="Silahkan scan QR Code Antrian atau masukan Kode Antrian"
                            placeholder="Masukan Kode Antrian untuk Checkin" igroup-size="lg">
                            <x-slot name="appendSlot">
                                <x-adminlte-button name="btn_checkin" id="btn_checkin" theme="success" label="Checkin!" />
                            </x-slot>
                            <x-slot name="prependSlot">
                                <div class="input-group-text text-success">
                                    <i class="fas fa-qrcode"></i>
                                </div>
                            </x-slot>
                        </x-adminlte-input>
                        <i class="fas fa-qrcode fa-3x"></i>
                        <br>
                        <label>Status = <span id="status">-</span></label>
                    </div>
                </x-adminlte-card>
                <div class="row">
                    <div class="col-md-6">
                        <x-adminlte-info-box class="btnDaftar" title="Daftar Pasien BPJS" text="Rujukan Pertama FKTP"
                            theme="success" />
                        <x-adminlte-info-box class="btnDaftar" title="Daftar Pasien BPJS" text="Rujukan Pertama Antar RS"
                            theme="success" />
                        <x-adminlte-info-box class="btnDaftar" title="Daftar Pasien BPJS" text="Rujukan Internal"
                            theme="success" />
                    </div>
                    <div class="col-md-6">
                        <x-adminlte-info-box class="btnDaftar" title="Daftar Pasien BPJS" text="Surat Kontrol"
                            theme="success" />
                        <x-adminlte-info-box class="btnDaftar" text="Daftar Pasien Umum" theme="success" />
                        <x-adminlte-button icon="fas fa-sync" class="withLoad reload" theme="warning" label="Reload" />
                        <a href="{{ route('antrian.cek_post') }}" class="btn btn-warning">Test Printer</a>
                    </div>
                </div>
            </div>
            {{-- ambil antrian offline --}}
            <div class="col-md-7">
                <p hidden>{{ setlocale(LC_ALL, 'IND') }}</p>
                <x-adminlte-card
                    title="Jadwal Dokter Poliklinik {{ \Carbon\Carbon::now()->formatLocalized('%A, %d %B %Y') }}"
                    theme="primary" icon="fas fa-qrcode">
                    <div class="row">
                        <div class="col-md-12">
                            @php
                                $heads = ['Poliklinik', 'Dokter', 'Jadwal', 'Kuota', 'Antrian'];
                                $config['order'] = ['5', 'asc'];
                            @endphp
                            <x-adminlte-datatable id="table1" class="nowrap text-xs" :heads="$heads" :config="$config"
                                striped bordered hoverable compressed>
                                @foreach ($poliklinik as $poli)
                                    @foreach ($poli->jadwals->where('hari', \Carbon\Carbon::now()->dayOfWeek)->where('kodesubspesialis', $poli->kodesubspesialis) as $jadwal)
                                        <tr
                                            class="text-left
                                            {{ $jadwal->libur == 1 ||$poli->antrians->where('tanggalperiksa', \Carbon\Carbon::now()->format('Y-m-d'))->where('taskid', '!=', 99)->where('kodedokter', $jadwal->kodedokter)->count() >= $jadwal->kapasitaspasien? ' text-danger': ' text-black' }}
                                           ">
                                            <td> {{ strtoupper($jadwal->namasubspesialis) }}</td>
                                            <td> {{ $jadwal->namadokter }} {{ $jadwal->libur ? '(TUTUP)' : '' }}</td>
                                            <td> {{ $jadwal->jadwal }}</td>
                                            <td> {{ $jadwal->kapasitaspasien }}</td>
                                            <td> {{ $poli->antrians->where('tanggalperiksa', \Carbon\Carbon::now()->format('Y-m-d'))->where('kodedokter', $jadwal->kodedokter)->where('taskid', '!=', 99)->count() }}
                                            </td>
                                        </tr>
                                    @endforeach
                                @endforeach
                            </x-adminlte-datatable>
                        </div>
                        {{-- @foreach ($poliklinik as $poli)
                                <div class="col-md-3">
                                    <x-adminlte-info-box
                                        text="{{ $poli->antrians->where('tanggalperiksa', \Carbon\Carbon::now()->format('Y-m-d'))->where('taskid', '!=', 99)->count() }} / {{ $poli->jadwals->where('hari', \Carbon\Carbon::now()->dayOfWeek)->where('kodesubspesialis', $poli->kodesubspesialis)->sum('kapasitaspasien') }}"
                                        title="{{ $poli->namasubspesialis }} " class="tombolPoli"
                                        data-id="{{ $poli->kodesubspesialis }}"
                                        theme="{{ $poli->antrians->where('tanggalperiksa', \Carbon\Carbon::now()->format('Y-m-d'))->count() >=$poli->jadwals->where('hari', \Carbon\Carbon::now()->dayOfWeek)->where('kodesubspesialis', $poli->kodesubspesialis)->sum('kapasitaspasien')? 'danger': 'success' }}" />
                                </div>
                            @endforeach --}}
                    </div>
                </x-adminlte-card>
            </div>
        </div>
    </div>
    {{-- Pilih Dokter --}}
    <x-adminlte-modal id="modalDokter" size="lg" title="Daftar Pasien Anjungan Mandiri" theme="success"
        icon="fas fa-user-md">
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
            <div class="row">
                <div class="col-md-6">
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
                            placeholder="Pilih Tanggal Surat Kontrol ..."
                            value="{{ Carbon\Carbon::now()->format('Y-m-d') }}">
                            <x-slot name="prependSlot">
                                <div class="input-group-text bg-primary">
                                    <i class="fas fa-calendar-alt"></i>
                                </div>
                            </x-slot>
                        </x-adminlte-input-date>
                        <x-adminlte-select2 name="pilihkodepoli" id="pilihkodepoli" label="Poliklinik">
                            <option value="0" selected>PILIH POLIKLINIK</option>
                            @foreach ($poliklinik as $item)
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
                </div>
                <div class="col-md-6">
                    <x-adminlte-card title="Data Pasien Rawat Jalan" class="datapasien" theme="warning" collapsible>
                        <x-adminlte-select name="pilihjeniskunjungan" id="pilihjeniskunjungan"
                            label="Jenis Kunjungan Pasien">
                            <option value="0" selected>PILIH JENIS KUNJUNGAN PASIEN</option>
                            <option value="1">BPJS Rujukan Faskes 1</option>
                            <option value="2">BPJS Rujukan Internal</option>
                            <option value="3">BPJS Surat Kontrol</option>
                            <option value="4">BPJS Rujukan Antar RS</option>
                            <option value="5">UMUM (NON-JKN)</option>
                        </x-adminlte-select>
                        <input type="hidden" name="jeniskunjungan" id="jeniskunjungan">
                        <div class="row">
                            <div class="col-md-6">
                                <x-adminlte-input fgroup-class="nama" name="nama" label="Nama Pasien" />
                            </div>
                            <div class="col-md-6">
                                <x-adminlte-input fgroup-class="norm" name="norm" label="No RM Pasien" />
                            </div>
                        </div>
                        <x-adminlte-input fgroup-class="nomorkartu" name="nomorkartu" label="No Kartu BPJS"
                            type="number">
                            <x-slot name="appendSlot">
                                <x-adminlte-button name="btn_check_nomorkartu" id="btn_check_nomorkartu" theme="success"
                                    label="Cek" />
                            </x-slot>
                        </x-adminlte-input>
                        <x-adminlte-input fgroup-class="nik" name="nik" label="NIK" type="number">
                            <x-slot name="appendSlot">
                                <x-adminlte-button name="btn_check_nik" id="btn_check_nik" theme="success"
                                    label="Cek" />
                            </x-slot>
                        </x-adminlte-input>
                        <x-adminlte-input fgroup-class="nohp" name="nohp" label="Nomor HP Pasien" />
                        <x-adminlte-select name="nomorreferensi" fgroup-class="nomorreferensi" label="Nomor Referensi">
                            <option value="0" selected>PILIH NOMOR REFERENSI</option>
                        </x-adminlte-select>
                        <x-slot name="footerSlot">
                            {{-- <x-adminlte-button icon="fas fa-user-md" id="daftar_pasien" theme="success" label="Daftar Pasien" /> --}}
                            <button type="submit" id="btnSubmitDaftar" form="formDaftarPasien" value="Submit"
                                class="mr-auto btn btn-success withLoad">Buat Surat Kontrol</button>
                            <x-adminlte-button icon="fas fa-sync" id="reset" theme="danger" label="Reset Pasien" />
                        </x-slot>
                    </x-adminlte-card>
                </div>
            </div>
        </form>
    </x-adminlte-modal>
@stop
{{-- @section('plugins.Sweetalert2', true); --}}
{{-- @section('plugins.Datatables', true) --}}
{{-- @section('plugins.TempusDominusBs4', true) --}}
@include('sweetalert::alert')
@section('adminlte_css')
    <script src="{{ asset('vendor/tempusdominus-bootstrap-4/css/tempusdominus-bootstrap-4.min.css') }}"></script>
@endsection
@section('adminlte_js')
    <script src="{{ asset('vendor/moment/moment.min.js') }}"></script>
    <script src="{{ asset('vendor/tempusdominus-bootstrap-4/js/tempusdominus-bootstrap-4.min.js') }}"></script>
    <script src="{{ asset('vendor/loading-overlay/loadingoverlay.min.js') }}"></script>
    <script src="{{ asset('vendor/onscan.js/onscan.min.js') }}"></script>
    <script src="{{ asset('vendor/sweetalert/sweetalert.all.js') }}"></script>
    <script src="{{ asset('vendor/sweetalert2/sweetalert2.all.min.js') }}"></script>
    {{-- scan --}}
    <script>
        $(function() {
            onScan.attachTo(document, {
                onScan: function(sCode, iQty) {
                    $.LoadingOverlay("show", {
                        text: "Printing..."
                    });
                    var url = "{{ route('antrian.checkin_update') }}";
                    var formData = {
                        kodebooking: sCode,
                        waktu: "{{ \Carbon\Carbon::now()->timestamp * 1000 }}",
                    };
                    $('#kodebooking').val(sCode);
                    $.get(url, formData, function(data) {
                        console.log(data);
                        $.LoadingOverlay("hide");
                        if (data.metadata.code == 200) {
                            $('#status').html(data.metadata.message);
                            swal.fire(
                                'Sukses...',
                                data.metadata.message,
                                'success'
                            ).then(okay => {
                                if (okay) {
                                    $.LoadingOverlay("show", {
                                        text: "Reload..."
                                    });
                                    $('#status').html('-');
                                    location.reload();
                                }
                            });
                        } else {
                            $('#status').html(data.metadata.message);
                            swal.fire(
                                'Opss Error...',
                                data.metadata.message,
                                'error'
                            ).then(okay => {
                                if (okay) {
                                    $.LoadingOverlay("show", {
                                        text: "Reload..."
                                    });
                                    $('#status').html('-');
                                    location.reload();
                                }
                            });
                        }
                    });
                },
            });
        });
    </script>
    {{-- btn chekin --}}
    <script>
        $(function() {
            $('#btn_checkin').click(function() {
                var kodebooking = $('#kodebooking').val();
                $.LoadingOverlay("show", {
                    text: "Printing..."
                });
                var url = "{{ route('antrian.checkin_update') }}";
                var formData = {
                    kodebooking: kodebooking,
                    waktu: "{{ \Carbon\Carbon::now()->timestamp * 1000 }}",
                };
                $('#kodebooking').val(kodebooking);
                $.get(url, formData, function(data) {
                    console.log(data);
                    $.LoadingOverlay("hide");
                    if (data.metadata.code == 200) {
                        $('#status').html(data.metadata.message);
                        swal.fire(
                            'Sukses...',
                            data.metadata.message,
                            'success'
                        ).then(okay => {
                            if (okay) {
                                $.LoadingOverlay("show", {
                                    text: "Reload..."
                                });
                                $('#status').html('-');
                                location.reload();
                            }
                        });
                    } else {
                        $('#status').html(data.metadata.message);
                        swal.fire(
                            'Opss Error...',
                            data.metadata.message,
                            'error'
                        ).then(okay => {
                            if (okay) {
                                $.LoadingOverlay("show", {
                                    text: "Reload..."
                                });
                                $('#status').html('-');
                                location.reload();
                            }
                        });
                    }
                });
            });
        });
    </script>
    {{-- btn daftar --}}
    <script>
        $(function() {
            $('.btnDaftar').click(function() {
                $('#modalDokter').modal('show');
            });
        });
    </script>
    <script>
        $(function() {
            $('.kodedokter').hide();
            $('.datapasien').hide();
            $('.nik').hide();
            $('.nomorkartu').hide();
            $('.nama').hide();
            $('.norm').hide();
            $('.nohp').hide();
            $('#btnSubmitDaftar').hide();
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
    {{-- withLoad --}}
    <script>
        $(function() {
            $(".withLoad").click(function() {
                $.LoadingOverlay("show");
            });
        })
        $('.reload').click(function() {
            location.reload();
        });
    </script>
@stop
