@extends('adminlte::page')
@section('title', 'Kunjungan')
@section('content_header')
    <h1>Kunjungan</h1>
@stop
@section('content')
    <div class="row">
        <div class="col-md-3">
            <x-adminlte-small-box title="{{ $kunjungans->total() }}" text="Total Kunjungan" theme="success"
                icon="fas fa-users" />
        </div>
        <div class="col-12">
            <x-adminlte-card title="Tabel Data Kunjungan" theme="secondary" collapsible>
                <div class="dataTables_wrapper dataTable">
                    <div class="row">
                        <div class="col-md-8">
                            <x-adminlte-button label="Tambah" class="btn-sm" theme="success" title="Tambah Kunjungan"
                                icon="fas fa-plus" data-toggle="modal" data-target="#modalCustom" />
                            <x-adminlte-button label="Export" class="btn-sm" theme="primary" title="Tooltip"
                                icon="fas fa-print" />
                        </div>
                        <div class="col-md-4">
                            <form action="#" method="get">
                                <x-adminlte-input name="search" placeholder="Pencarian NIK / Nama" igroup-size="sm"
                                    value="{{ $request->search }}">
                                    <x-slot name="appendSlot">
                                        <x-adminlte-button type="submit" theme="outline-primary" label="Go!" />
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
                    <div class="row">
                        <div class="col-md-12">
                            @php
                                $heads = ['Counter', 'Tgl Masuk', 'Tgl Keluar', 'Kode Kunjungan', 'RM Pasien', 'Unit / Dokter', 'Penjamin', 'Alasan Masuk', 'Status', 'Action'];
                                $config['paging'] = false;
                                $config['lengthMenu'] = false;
                                $config['searching'] = false;
                                $config['info'] = false;
                                $config['order'] = [[1, 'desc']];
                            @endphp
                            <x-adminlte-datatable id="table1" class="nowrap" :heads="$heads" :config="$config"
                                hoverable bordered compressed>
                                @foreach ($kunjungans as $item)
                                    <tr>
                                        <td>{{ $item->counter }}</td>
                                        <td>{{ $item->tgl_masuk }}</td>
                                        <td>{{ $item->tgl_keluar }}</td>
                                        <td>{{ $item->kode_kunjungan }}</td>
                                        <td>
                                            {{ $item->no_rm }} <br>
                                            {{ $item->pasien->nama_px ?? '-' }}
                                        </td>
                                        <td>
                                            {{ $item->unit->nama_unit ?? '-' }} <br>
                                            {{ $item->dokter->nama_paramedis ?? '-' }}
                                        </td>
                                        <td>{{ $item->penjamin_simrs->nama_penjamin ?? '-' }}</td>
                                        <td>{{ $alasan_masuk[$item->id_alasan_masuk] ?? '-' }}</td>
                                        <td>{{ $status_kunjungan[$item->status_kunjungan] }}</td>
                                        <td>
                                            <x-adminlte-button class="btn-xs" theme="warning" icon="fas fa-edit"
                                                onclick="window.location='{{ route('kunjungan.edit', $item->kode_kunjungan) }}'" />
                                            </form>
                                        </td>
                                    </tr>
                                @endforeach
                            </x-adminlte-datatable>
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-5">
                            <div class="dataTables_info">
                                Tampil {{ $kunjungans->firstItem() }} s/d {{ $kunjungans->lastItem() }} dari total
                                {{ $kunjungans->total() }}
                            </div>
                        </div>
                        <div class="col-md-7">
                            <div class="dataTables_paginate pagination-sm">
                                {{ $kunjungans->appends(['periode' => $request->periode])->links() }}
                            </div>
                        </div>
                    </div>
                </div>
            </x-adminlte-card>
            <x-adminlte-alert title="Catatan Informasi" theme="info" dismissable>
                Data pada halaman diambil pada waktu {{ \Carbon\Carbon::now() }}
            </x-adminlte-alert>
        </div>
    </div>
@stop

@section('plugins.Datatables', true)
@section('plugins.DateRangePicker', true)
@section('plugins.TempusDominusBs4', true)
