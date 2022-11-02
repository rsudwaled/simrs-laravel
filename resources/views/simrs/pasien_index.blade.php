@extends('adminlte::page')
@section('title', 'Pasien')
@section('content_header')
    <h1>Pasien</h1>
@stop
@section('content')
    <div class="row">
        <div class="col-md-3">
            <x-adminlte-small-box title="{{ $total_pasien }}" text="Total Pasien" theme="success" icon="fas fa-users" />
        </div>
        <div class="col-md-3">
            <x-adminlte-small-box title="{{ $pasien_jkn }} {{ round(($pasien_jkn / $total_pasien) * 100) }}%"
                text="Pasien memiliki Kartu" theme="warning" icon="fas fa-users" />
        </div>
        <div class="col-md-3">
            <x-adminlte-small-box title="{{ $pasien_nik }} {{ round(($pasien_jkn / $total_pasien) * 100) }}%"
                text="Pasien memiliki NIK" theme="warning" icon="fas fa-users" />
        </div>
        <div class="col-12">
            <x-adminlte-card title="Grafik Pasien" theme="secondary" collapsible="collapsed">
                asdasd
            </x-adminlte-card>
            <x-adminlte-card title="Data Pasien" theme="secondary" collapsible>
                <div class="row">
                    <div class="col-md-8">
                        <x-adminlte-button label="Tambah" class="btn-sm" theme="success" title="Tambah Pasien"
                            icon="fas fa-plus" data-toggle="modal" data-target="#modalCustom" />
                    </div>
                    <div class="col-md-4">
                        <form action="{{ route('pasien.index') }}" method="get">
                            <x-adminlte-input name="search" placeholder="Pencarian NIK / Nama" igroup-size="sm"
                                value="{{ $request->search }}">
                                <x-slot name="appendSlot">
                                    <x-adminlte-button type="submit" theme="outline-primary" label="Cari" />
                                </x-slot>
                                <x-slot name="prependSlot">
                                    <div class="input-group-text text-primary">
                                        <i class="fas fa-search"></i>
                                    </div>
                                </x-slot>
                            </x-adminlte-input>
                        </form>
                    </div>
                </div>
                @php
                    $heads = ['Kode RM', 'BPJS', 'NIK', 'Nama Pasien (Umur)', 'Sex', 'Kecamatan', 'Alamat', 'Tgl Entry', 'Action'];
                    $config['paging'] = false;
                    $config['lengthMenu'] = false;
                    $config['searching'] = false;
                    $config['info'] = false;
                    $config['responsive'] = true;
                @endphp
                <x-adminlte-datatable id="table1" :heads="$heads" :config="$config" hoverable bordered compressed>
                    @foreach ($pasiens as $item)
                        <tr>
                            <td>{{ $item->no_rm }}</td>
                            <td>{{ $item->no_Bpjs }}</td>
                            <td>{{ $item->nik_bpjs }}</td>
                            <td>{{ $item->nama_px }} ({{ \Carbon\Carbon::parse($item->tgl_lahir)->age }})</td>
                            <td>{{ $item->jenis_kelamin }}</td>
                            <td>{{ $item->kecamatans->nama_kecamatan }}</td>
                            <td>{{ $item->alamat }}</td>
                            <td>{{ $item->tgl_entry }} ({{ $item->pic }})</td>
                            <td>
                                <form action="{{ route('pasien.destroy', $item->no_rm) }}" method="POST">
                                    <x-adminlte-button class="btn-xs" theme="warning" icon="fas fa-edit"
                                        onclick="window.location='{{ route('pasien.edit', $item->no_rm) }}'" />
                                    @csrf
                                    @method('DELETE')
                                    <x-adminlte-button class="btn-xs" theme="danger" icon="fas fa-trash-alt" type="submit"
                                        onclick="return confirm('Apakah anda akan menghapus {{ $item->no_rm }} ?')" />
                                </form>
                            </td>
                        </tr>
                    @endforeach
                </x-adminlte-datatable>
                <div class="row">
                    <div class="col-md-5">
                        Tampil data {{ $pasiens->firstItem() }} sampai {{ $pasiens->lastItem() }} dari total
                        {{ $total_pasien }}
                    </div>
                    <div class="col-md-7">
                        <div class="float-right pagination-sm">
                            {{ $pasiens->links() }}
                        </div>
                    </div>
                </div>
            </x-adminlte-card>
        </div>
    </div>
    <x-adminlte-modal id="modalCustom" title="Tambah User" theme="success" size="lg" v-centered static-backdrop
        scrollable>
        <form action="{{ route('pasien.store') }}" id="myform" method="post">
            @csrf
            <div class="row">
                <div class="col-md-6">
                    <x-adminlte-input name="nik" label="NIK" placeholder="Nomor Induk Kependudukan"
                        enable-old-support required />
                    <x-adminlte-input name="name" label="Nama" placeholder="Nama Lengkap" enable-old-support
                        required />
                    <div class="row">
                        <div class="col-md-6">
                            <x-adminlte-input name="tempat_lahir" label="Tempat Lahir" placeholder="Tempat Lahir"
                                enable-old-support required />
                        </div>
                        <div class="col-md-6">
                            @php
                                $config = ['format' => 'DD-MM-YYYY'];
                            @endphp
                            <x-adminlte-input-date name="tanggal_lahir" label="Tanggal Lahir" placeholder="Tanggal Lahir"
                                :config="$config" enable-old-support required />
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-6">
                            <x-adminlte-select name="gender" label="Jenis Kelamin" enable-old-support>
                                <x-adminlte-options :options="['Laki-Laki', 'Perempuan']" placeholder="Jenis Kelamin" />
                            </x-adminlte-select>
                            <x-adminlte-select name="Agama" label="Agama" enable-old-support>
                                <x-adminlte-options :options="['Islam', 'Perempuan']" placeholder="Agama" />
                            </x-adminlte-select>
                            <x-adminlte-select name="perkawinan" label="Status Perkawinan" enable-old-support>
                                <x-adminlte-options :options="['Islam', 'Perempuan']" placeholder="Status Perkawinan" />
                            </x-adminlte-select>
                        </div>
                        <div class="col-md-6">
                            <x-adminlte-input name="pekerjaan" label="Pekerjaan" placeholder="Pekerjaan"
                                enable-old-support />
                            <x-adminlte-input name="kewarganegaraan" label="Kewarganegaraan"
                                placeholder="Kewarganegaraan" enable-old-support />
                            <x-adminlte-select name="darah" label="Golongan Darah" enable-old-support>
                                <x-adminlte-options :options="['A', 'B', 'AB', 'O']" placeholder="Golongan Darah" />
                            </x-adminlte-select>
                        </div>
                    </div>
                </div>
            </div>
        </form>
        <x-slot name="footerSlot">
            <x-adminlte-button form="myform" class="mr-auto" type="submit" theme="success" label="Simpan" />
            <x-adminlte-button theme="danger" label="Kembali" data-dismiss="modal" />
        </x-slot>
    </x-adminlte-modal>
@stop

@section('plugins.Datatables', true)
@section('plugins.Select2', true)
@section('plugins.TempusDominusBs4', true)
