@extends('adminlte::page')

@section('title', 'Pemanggilan Antrian Online')

@section('content_header')
    <h1>Pemanggilan Antrian Online</h1>
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
            <x-adminlte-card title="Filter Data Antrian" theme="secondary" collapsible>
                <form action="{{ route('antrianwa.index') }}" method="get">
                    @php
                        $config = ['format' => 'DD-MM-YYYY'];
                    @endphp
                    <x-adminlte-input-date name="tanggal" label="Tanggal Antrian" :config="$config"
                        value="{{ \Carbon\Carbon::parse($request->tanggal)->format('d-m-Y') }}">
                        <x-slot name="prependSlot">
                            <div class="input-group-text bg-primary">
                                <i class="fas fa-calendar-alt"></i>
                            </div>
                        </x-slot>
                    </x-adminlte-input-date>
                    <div class="row">
                        <div class="col-md-6">
                            <x-adminlte-select name="loket" label="Loket">
                                <x-adminlte-options
                                    :options="[1 => 'Loket 1' , 2 => 'Loket 2' , 3 => 'Loket 3' , 4 => 'Loket 4' ,5 => 'Loket 5'  ]"
                                    :selected="$request->loket ?? 1" />
                            </x-adminlte-select>
                        </div>
                        <div class="col-md-6">
                            <x-adminlte-select name="lantai" label="Lantai">
                                <x-adminlte-options :options="[1 =>'Lantai 1' , 2 =>'Lantai 2'  ]" />
                            </x-adminlte-select>
                        </div>
                    </div>
                    <x-adminlte-button type="submit" class="withLoad" theme="primary" label="Submit Antrian" />
                </form>
            </x-adminlte-card>
            @isset($request->loket)
                <div class="row">
                    <div class="col-md-3">
                        <x-adminlte-small-box title="{{ $antrians->where('status', 2)->first()->no_urut ?? '0' }}"
                            text="Antrian Saat Ini" theme="primary" class="withLoad" icon="fas fa-sign-in-alt"
                            url="{{ route('antrianwa.batal', [$request->tanggal, $antrians->where('status', 2)->first()->no_urut ?? '0']) }}"
                            url-text="Batalkan Antrian" />
                    </div>
                    <div class="col-md-3">
                        <x-adminlte-small-box title="{{ $antrians->where('status', 1)->first()->no_urut ?? '0' }}"
                            class="withLoad" text="Antrian Selanjutnya" theme="success" icon="fas fa-sign-in-alt"
                            url="{{ route('antrianwa.panggil', [$request->tanggal,$antrians->where('status', 1)->first()->no_urut ?? '0',$request->loket,$request->lantai]) }}"
                            url-text="Panggil Antrian Selanjutnya" />
                    </div>
                    <div class="col-md-3">
                        <x-adminlte-small-box title="{{ $sisa_antrian }}" text="Sisa Antrian" theme="warning"
                            icon="fas fa-sign-in-alt" />
                    </div>
                    <div class="col-md-3">
                        <x-adminlte-small-box title="{{ $antrians->count() }}" text="Total Antrian" theme="success"
                            icon="fas fa-sign-in-alt" />
                    </div>
                </div>
                <x-adminlte-card title="Tabel Antrian Dalam Proses" theme="primary" collapsible>
                    <div class="dataTables_wrapper dataTable">
                        <div class="row">
                            <div class="col-md-12">
                                @php
                                    $heads = ['Urutan', 'Tanggal/Kode', 'Nama/Tipe/Poliklinik', 'Detail Pasien', 'Waktu Dipanggil', 'Status', 'Action'];
                                    $config['paging'] = false;
                                    $config['lengthMenu'] = false;
                                    $config['searching'] = false;
                                    $config['info'] = false;
                                    $config['responsive'] = true;
                                @endphp
                                <x-adminlte-datatable id="table2" :heads="$heads" :config="$config" hoverable bordered
                                    compressed>
                                    @foreach ($antrians->where('status', 2) as $antrian)
                                        <tr>
                                            <td>{{ $antrian->no_urut }}</td>
                                            <td>{{ $antrian->tanggal }}<br>{{ $antrian->kode_antrian }}</td>
                                            <td>{{ $antrian->nama_antrian }}<br>{{ $antrian->tipe }}<br>{{ $antrian->unit->nama_unit }}
                                            </td>
                                            <td>
                                                @isset($antrian->no_rm)
                                                    <b>No RM :</b> {{ $antrian->no_rm }}<br>
                                                @endisset
                                                @isset($antrian->nama)
                                                    <b>Nama :</b> {{ $antrian->nama }}<br>
                                                @endisset
                                                @isset($antrian->nik)
                                                    <b>NIK :</b> {{ $antrian->nik }}<br>
                                                @endisset
                                                @isset($antrian->no_bpjs)
                                                    <b>BPJS :</b> {{ $antrian->no_bpjs }}<br>
                                                @endisset
                                                @isset($antrian->phone)
                                                    <b>No WA :</b> {{ $antrian->phone }}<br>
                                                @endisset
                                            </td>
                                            <td>{{ \Carbon\Carbon::parse($antrian->updated_at)->format('H:i:s') }} <br>
                                                <span
                                                    class="badge bg-danger">{{ \Carbon\Carbon::parse($antrian->updated_at)->addMinutes(5)->format('H:i:s') }}
                                                </span>
                                            </td>
                                            <td>
                                                @if ($antrian->status == 1)
                                                    <span class="badge bg-warning">{{ $antrian->status }}. Tunggu
                                                        pendaftaran</span>
                                                @endif
                                                @if ($antrian->status == 2)
                                                    <span class="badge bg-primary">{{ $antrian->status }}. Proses
                                                        pendaftaran</span>
                                                @endif
                                                @if ($antrian->status == 3)
                                                    <span class="badge bg-success">{{ $antrian->status }}. Tunggu poli</span>
                                                @endif
                                                @if ($antrian->status == 99)
                                                    <span class="badge bg-danger">{{ $antrian->status }}. Batal
                                                        antrian</span>
                                                @endif
                                            </td>
                                            <td>
                                                <x-adminlte-button class="btn-xs withLoad" label="Selesai" theme="success"
                                                    icon="fas fa-check" data-toggle="tooltop"
                                                    title="Antrian selesai dan panggil antrian berikutnya"
                                                    onclick="window.location='{{ route('antrianwa.selesai', [$request->tanggal, $antrian->no_urut]) }}'" />
                                                <x-adminlte-button class="btn-xs withLoad" label="Panggil Ulang" theme="warning"
                                                    icon="fas fa-check" data-toggle="tooltop" title="Panggil Ulang Antrian"
                                                    onclick="window.location='{{ route('antrianwa.panggil_ulang', [$request->tanggal, $antrian->no_urut, $request->loket, $request->lantai]) }}'" />
                                                <x-adminlte-button class="btn-xs withLoad" label="Konfirmasi" theme="danger"
                                                    icon="fas fa-times" data-toggle="tooltop"
                                                    title="Antrian dibatalkan dan panggil antrian berikutnya"
                                                    onclick="window.location='{{ route('antrianwa.batal', [$request->tanggal, $antrian->no_urut]) }}'" />
                                            </td>
                                        </tr>
                                    @endforeach
                                </x-adminlte-datatable>
                            </div>
                        </div>
                    </div>
                </x-adminlte-card>
                <x-adminlte-card title="Tabel Antrian" theme="secondary" collapsible>
                    <div class="dataTables_wrapper dataTable">
                        <div class="row">
                            <div class="col-md-7">
                                @php
                                    $heads = ['Urutan', 'Tanggal/Kode', 'Nama/Tipe', 'No WA', 'Status'];
                                    $config['paging'] = false;
                                    $config['lengthMenu'] = false;
                                    $config['searching'] = true;
                                    $config['responsive'] = true;
                                    $config['order'] = ['4', 'asc'];
                                    $config['scrollY'] = 500;
                                @endphp
                                <x-adminlte-datatable id="table1" :heads="$heads" :config="$config" hoverable bordered
                                    compressed>
                                    @foreach ($antrians as $antrian)
                                        <tr>
                                            <td>{{ $antrian->no_urut }}</td>
                                            <td>{{ $antrian->tanggal }}<br>{{ $antrian->kode_antrian }}</td>
                                            <td>{{ $antrian->nama_antrian }}<br>{{ $antrian->tipe }} /
                                                {{ $antrian->unit->nama_unit }}</td>
                                            <td>{{ $antrian->phone }}</td>
                                            <td>
                                                @if ($antrian->status == 0)
                                                    <span class="badge bg-danger">{{ $antrian->status }}. Belum Checkin</span>
                                                @endif
                                                @if ($antrian->status == 1)
                                                    <span class="badge bg-warning">{{ $antrian->status }}. Tunggu
                                                        pendaftaran</span>
                                                @endif
                                                @if ($antrian->status == 2)
                                                    <span class="badge bg-primary">{{ $antrian->status }}. Proses
                                                        pendaftaran</span>
                                                @endif
                                                @if ($antrian->status == 3)
                                                    <span class="badge bg-success">{{ $antrian->status }}. Tunggu poli</span>
                                                @endif
                                                @if ($antrian->status == 97)
                                                    <span class="badge bg-secondary">{{ $antrian->status }}. Daftar
                                                        Ulang</span>
                                                @endif
                                                @if ($antrian->status == 98)
                                                    <span class="badge bg-warning">{{ $antrian->status }}. Dalam
                                                        Konfirmasi</span>
                                                @endif
                                                @if ($antrian->status == 99)
                                                    <span class="badge bg-danger">{{ $antrian->status }}. Batal
                                                        antrian</span>
                                                @endif
                                            </td>
                                        </tr>
                                    @endforeach
                                </x-adminlte-datatable>
                            </div>
                            <div class="col-md-5">
                                @php
                                    $heads = ['Urutan', 'Tanggal/Kode', 'Status'];
                                    $config['paging'] = false;
                                    $config['lengthMenu'] = false;
                                    $config['searching'] = true;
                                    $config['responsive'] = true;
                                    $config['order'] = ['0', 'asc'];
                                    $config['scrollY'] = 500;
                                @endphp
                                <x-adminlte-datatable id="table3" :heads="$heads" :config="$config" hoverable bordered
                                    compressed>
                                    @foreach ($antrians->where('status', 98) as $antrian)
                                        <tr>
                                            <td>{{ $antrian->no_urut }}</td>
                                            <td>{{ $antrian->nama_antrian }}<br>{{ $antrian->kode_antrian }}</td>
                                            <td>
                                                @if ($antrian->status == 1)
                                                    <span class="badge bg-warning">{{ $antrian->status }}. Tunggu
                                                        pendaftaran</span>
                                                @endif
                                                @if ($antrian->status == 2)
                                                    <span class="badge bg-primary">{{ $antrian->status }}. Proses
                                                        pendaftaran</span>
                                                @endif
                                                @if ($antrian->status == 3)
                                                    <span class="badge bg-success">{{ $antrian->status }}. Tunggu poli</span>
                                                @endif
                                                @if ($antrian->status == 97)
                                                    <span class="badge bg-warning">{{ $antrian->status }}. Daftar
                                                        Ulang</span>
                                                @endif
                                                @if ($antrian->status == 98)
                                                    <span class="badge bg-warning">{{ $antrian->status }}. Dalam
                                                        Konfirmasi</span>
                                                @endif
                                                @if ($antrian->status == 99)
                                                    <span class="badge bg-danger">{{ $antrian->status }}. Batal
                                                        antrian</span>
                                                @endif
                                            </td>
                                        </tr>
                                    @endforeach
                                </x-adminlte-datatable>
                            </div>
                        </div>
                    </div>
                </x-adminlte-card>
            @endisset
        </div>
    </div>
    {{-- <x-adminlte-modal id="modalCustom" title="Tambah Antrian" theme="success" v-centered static-backdrop scrollable>
        <form action="{{ route('antrian.store') }}" id="myform" method="post">
            @csrf
            <x-adminlte-select2 name="tipe" label="Tipe Pasien" enable-old-support required>
                <x-adminlte-options :options="['UMUM'=>'UMUM','BPJS'=>'BPJS']" placeholder="Pilih Tipe Pasien" />
            </x-adminlte-select2>
            <x-adminlte-input name="nik" label="NIK" placeholder="Nomor Induk Kependudukan" enable-old-support required />
            <x-adminlte-input name="nama" label="Nama" placeholder="Nama Lengkap" enable-old-support required />
            <x-adminlte-input name="phone" type="number" label="Nomor HP / Telepon"
                placeholder="Nomor HP / Telepon yang dapat dihubungi" enable-old-support required />
            <x-adminlte-select2 name="kode_poli" label="Poliklinik" enable-old-support required>
                <x-adminlte-options :options=$poli placeholder="Pilih Poliklinik" />
            </x-adminlte-select2>
            @php
                $config = ['format' => 'DD-MM-YYYY'];
            @endphp
            <x-adminlte-input-date name="tanggal" label="Tanggal" :config="$config"
                value="{{ \Carbon\Carbon::today()->format('d-m-Y') }}" />
        </form>
        <x-slot name="footerSlot">
            <x-adminlte-button form="myform" class="mr-auto" type="submit" theme="success" label="Simpan" />
            <x-adminlte-button theme="danger" label="Kembali" data-dismiss="modal" />
        </x-slot>
    </x-adminlte-modal> --}}
@stop
@section('plugins.Datatables', true)
{{-- @section('plugins.Select2', true) --}}
@section('plugins.TempusDominusBs4', true)
