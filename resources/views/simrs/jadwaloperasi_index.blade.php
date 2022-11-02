@extends('adminlte::page')

@section('title', 'Jadwal Operasi')

@section('content_header')
    <h1>Jadwal Operasi</h1>
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
            <x-adminlte-card title="Jadwal Operasi RSUD Waled" theme="info" icon="fas fa-info-circle" collapsible>
                @php
                    $heads = ['Tanggal', 'Kode Booking', 'Jenis Tindakan', 'Poliklinik', 'Dokter', 'Pasien', 'Status', 'Action'];
                @endphp
                <x-adminlte-datatable id="table1" :heads="$heads" striped bordered hoverable compressed>
                    @foreach ($jadwals as $item)
                        <tr>
                            <td>{{ $item->tanggaloperasi }}</td>
                            <td>{{ $item->kodebooking }}</td>
                            <td>{{ $item->jenistindakan }}</td>
                            <td>{{ $item->kodepoli }} {{ $item->namapoli }}</td>
                            <td>{{ $item->kodedokter }} {{ $item->namadokter }}</td>
                            <td>{{ $item->nopeserta }}<br>
                                {{ $item->namapeserta }}</td>
                            <td>
                                @if ($item->terlaksana == 0)
                                    Belum
                                @else
                                    Sudah
                                @endif
                            </td>
                            <td>
                                <form action="{{ route('pasien.destroy', $item->kodebooking) }}" method="POST">
                                    {{-- <x-adminlte-button class="btn-xs" theme="warning" icon="fas fa-edit"
                                        onclick="window.location='{{ route('pasien.edit', $item->kodebooking) }}'" /> --}}
                                    @csrf
                                    @method('DELETE')
                                    <x-adminlte-button class="btn-xs" theme="danger" icon="fas fa-trash-alt" type="submit"
                                        onclick="return confirm('Apakah anda akan menghapus {{ $item->kodebooking }} ?')" />
                                </form>
                            </td>

                            {{-- <td>
                                @if ($item->status == 1)
                                    <a href="{{ route('dokter.show', $item->kodedokter) }}">
                                        <x-adminlte-button class="btn-xs" type="button" label="aktif" theme="success" />
                                    </a>
                                @else
                                    <a href="{{ route('dokter.show', $item->kodedokter) }}">
                                        <x-adminlte-button class="btn-xs" type="button" label="nonaktif" theme="danger" />
                                    </a>
                                @endif
                            </td> --}}
                        </tr>
                    @endforeach
                </x-adminlte-datatable>
                <x-adminlte-button label="Tambah Jadwal Operasi" theme="success" data-toggle="modal"
                    data-target="#jadwalOpeasiModal" />
                {{-- <a href="{{ route('dokter.create') }}" class="btn btn-success">Refresh</a> --}}
            </x-adminlte-card>
            {{-- Modal Update Jadwal --}}
            <x-adminlte-modal id="jadwalOpeasiModal" title="Tambah Jadwal Operasi" theme="warning"
                icon="fas fa-calendar-alt">
                <form name="formUpdateJadwal" id="formUpdateJadwal" action="{{ route('jadwaloperasi.store') }}"
                    method="POST">
                    @csrf
                    <input type="hidden" name="method" value="STORE">
                    <input type="hidden" class="idjadwal" name="idjadwal" id="idjadwal">
                    <x-adminlte-input name="nik" id="nik" label="NIK" placeholder="NIK" enable-old-support>
                        <x-slot name="appendSlot">
                            <x-adminlte-button name="cariNIK" id="cariNIK" theme="primary" label="Cari!" />
                        </x-slot>
                        <x-slot name="prependSlot">
                            <div class="input-group-text text-primary">
                                <i class="fas fa-search"></i>
                            </div>
                        </x-slot>
                        <x-slot name="bottomSlot">
                            <span id="pasienTidakDitemukan" class="text-sm text-danger"></span>
                            <span id="pasienDitemukan" class="text-sm text-success"></span>
                        </x-slot>
                    </x-adminlte-input>
                    <div class="row">
                        <div class="col-md-6">
                            <x-adminlte-input name="nopeserta" label="Nomor Kartu" placeholder="Nomor Kartu" />
                        </div>
                        <div class="col-md-6">
                            <x-adminlte-input name="norm" label="Nomor RM Pasien" placeholder="Nomor RM Pasien"
                                readonly />
                        </div>
                    </div>
                    <x-adminlte-input name="namapeserta" label="Nama Pasien" placeholder="Nama Pasien" />
                    <x-adminlte-select2 name="kodepoli" label="Poliklinik">
                        @foreach ($poli as $item)
                            <option value="{{ $item->kodesubspesialis }}">{{ $item->kodesubspesialis }} -
                                {{ $item->namasubspesialis }}
                            </option>
                        @endforeach
                    </x-adminlte-select2>
                    <x-adminlte-select2 name="kodedokter" id="kodedokter" label="Dokter">
                        @foreach ($dokters as $item)
                            <option value="{{ $item->kodedokter }}">{{ $item->kodedokter }} {{ $item->namadokter }}
                            </option>
                        @endforeach
                    </x-adminlte-select2>
                    <x-adminlte-input name="jenistindakan" label="Tindakan Operasi" placeholder="Tindankan Operasi"
                        enable-old-support />
                    @php
                        $config = ['format' => 'YYYY-MM-DD'];
                    @endphp
                    <x-adminlte-input-date name="tanggaloperasi" label="Tanggal Operasi"
                        value="{{ \Carbon\Carbon::now()->format('Y-m-d') }}" :config="$config">
                        <x-slot name="prependSlot">
                            <div class="input-group-text bg-primary">
                                <i class="fas fa-calendar-alt"></i>
                            </div>
                        </x-slot>
                    </x-adminlte-input-date>
                    <x-adminlte-input-switch name="terlaksana" label="Terlaksana" data-on-text="YES" data-off-text="NO"
                        data-on-color="primary" />

                </form>
                <x-slot name="footerSlot">
                    <x-adminlte-button label="Tambah" form="formUpdateJadwal" class="mr-auto withLoad" type="submit"
                        theme="success" icon="fas fa-edit" />
                    <x-adminlte-button theme="danger" icon="fas fa-times" label="Close" data-dismiss="modal" />
                </x-slot>
            </x-adminlte-modal>
        </div>
    </div>
@stop

@section('plugins.Select2', true)
@section('plugins.Datatables', true)
@section('plugins.TempusDominusBs4', true)
@section('plugins.DateRangePicker', true)
@section('plugins.BootstrapSwitch', true)
@section('js')
    {{-- js cari pasien baru / lama offline --}}
    <script>
        $(function() {
            $('#formPasien').hide();
            $('#cariNIK').on('click', function() {
                var nik = $('#nik').val();
                if (nik == '') {
                    alert('NIK tidak boleh kosong');
                } else {
                    $.LoadingOverlay("show");
                    $.get("{{ route('antrian.index') }}" + "/cari_pasien/" + nik, function(data) {
                        console.log(data.metadata.code);
                        if (data.metadata.code == 200) {
                            $('#pasienDitemukan').html(data.metadata.message);
                            $('#pasienTidakDitemukan').html('');
                            $('#nomorkk').val(data.response.no_ktp);
                            $('#nohp').val(data.response.no_tlp);
                            $('#namapeserta').val(data.response.nama_px);
                            $('#norm').val(data.response.no_rm);
                            $('#nopeserta').val(data.response.no_Bpjs);
                            $('#statuspasien').val('LAMA');
                            $('#formPasien').hide();
                        } else {
                            $('#pasienTidakDitemukan').html(data.metadata.message);
                            $('#pasienDitemukan').html('');
                            $('#nomorkk').val('');
                            $('#nohp').val('');
                            $('#nama').val('');
                            $('#norm').val('');
                            $('#nomorkartu').val('');
                            $('#statuspasien').val('BARU');
                            $('#formPasien').show();
                        }
                        $.LoadingOverlay("hide", true);
                    })
                }
            });
        });
    </script>
@endsection
