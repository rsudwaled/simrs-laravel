@extends('adminlte::page')

@section('title', 'Data Surat Kontrol')

@section('content_header')
    <h1>Data Surat Kontrol</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-md-12">
            @if ($errors->any())
                <x-adminlte-alert title="Ops Terjadi Masalah !" theme="danger" dismissable>
                    <ul>
                        @foreach ($errors->all() as $error)
                            <li>{{ $error }}</li>
                        @endforeach
                    </ul>
                </x-adminlte-alert>
            @endif
            <x-adminlte-card title="Pencarian Data Surat Kontrol" theme="secondary" collapsible>
                <div class="row">
                    <div class="col-md-6">
                        <form action="" id="myform" method="get">
                            {{-- @php
                                $config = ['format' => 'YYYY-MM-DD'];
                            @endphp
                            <x-adminlte-input-date name="tanggalsuratkontrol" label="Tanggal Surat Kontrol"
                                :config="$config"
                                value="{{ \Carbon\Carbon::parse($request->tanggalsuratkontrol)->format('Y-m-d') }}">
                                <x-slot name="prependSlot">
                                    <div class="input-group-text bg-primary">
                                        <i class="fas fa-calendar-alt"></i>
                                    </div>
                                    <x-slot name="appendSlot">
                                        <x-adminlte-button theme="success" class="withLoad" type="submit" label="Cari!" />
                                    </x-slot>
                                </x-slot>
                            </x-adminlte-input-date> --}}
                            @php
                                $config = [
                                    // 'showDropdowns' => true,
                                    'startDate' => 'js:moment()',
                                    'endDate' => "js:moment().subtract(1, 'days')",
                                    'minYear' => 2000,
                                    'timePicker' => false,
                                    'locale' => ['format' => 'YYYY/MM/DD'],
                                    'opens' => 'center',
                                ];
                            @endphp
                            <x-adminlte-date-range name="tanggalsuratkontrol" label="Tanggal Terbit Surat Kontrol"
                                :config="$config">
                                <x-slot name="prependSlot">
                                    <div class="input-group-text bg-primary">
                                        <i class="fas fa-calendar-alt"></i>
                                    </div>
                                    <x-slot name="appendSlot">
                                        <x-adminlte-button theme="success" class="withLoad" type="submit" label="Cari!" />
                                    </x-slot>
                                </x-slot>
                            </x-adminlte-date-range>
                        </form>
                    </div>
                </div>
            </x-adminlte-card>
            @empty($suratkontrols)
                <x-adminlte-alert title="Informasi !" theme="info" dismissable>
                    Silahkan lakukan pencarian berdasarkan NIK atau Nomor Kartu BPJS
                </x-adminlte-alert>
            @else
                <x-adminlte-card title="Data Surat Kontrol" theme="primary" collapsible>
                    <div class="row">
                        <div class="col-md-12">
                            @php
                                $heads = ['Tgl Surat', 'Tgl Terbit', 'No Surat Kontrol', 'No SEP', 'Jenis Pelayanan', 'Poliklinik', 'Diagnosa', 'Terbit SEP', 'Action'];
                                $config['order'] = ['7', 'asc'];
                            @endphp
                            <x-adminlte-datatable id="table1" class="nowrap" :heads="$heads" :config="$config" striped
                                bordered hoverable compressed>
                                @foreach ($suratkontrols as $item)
                                    <tr>
                                        <td>{{ $item->tglRencanaKontrol }}</td>
                                        <td>{{ $item->tglTerbitKontrol }}</td>
                                        <td>{{ $item->noSuratKontrol }}</td>
                                        <td>{{ $item->noSepAsalKontrol }} <br>{{ $item->tglSEP }}</td>
                                        <td>{{ $item->namaPoliAsal }} <br>{{ $item->namaPoliTujuan }}</td>
                                        <td>{{ $item->kodeDokter }} <br>{{ $item->namaDokter }}</td>
                                        <td>{{ $item->noKartu }} <br>{{ $item->nama }}</td>
                                        <td>{{ $item->terbitSEP }}</td>
                                        <td>
                                            <form action="{{ route('vclaim.delete_surat_kontrol', $item->noSuratKontrol) }}"
                                                method="POST">
                                                @csrf
                                                @method('DELETE')
                                                <x-adminlte-button class="btn-xs" theme="danger" icon="fas fa-trash-alt"
                                                    type="submit"
                                                    onclick="return confirm('Apakah anda akan menghapus {{ $item->noSuratKontrol }} ?')" />
                                            </form>
                                        </td>
                                    </tr>
                                @endforeach
                            </x-adminlte-datatable>
                        </div>
                    </div>
                </x-adminlte-card>


            @endisset
        </div>
    </div>
@stop

{{-- @section('plugins.Select2', true) --}}
@section('plugins.Datatables', true)
@section('plugins.TempusDominusBs4', true)
@section('plugins.DateRangePicker', true)
