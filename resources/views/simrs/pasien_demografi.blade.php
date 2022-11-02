@extends('adminlte::page')
@section('title', 'Pasien Berdasarkan Demografi')
@section('content_header')
    <h1>Pasien Berdasarkan Demografi</h1>
@stop
@section('content')
    <div class="row">
        <div class="col-6">
            <x-adminlte-card title="Data Pasien Berdasarkan 20 Kecataman Teratas" theme="secondary" collapsible>
                @php
                    $heads = ['Kode Kecamatan', 'Nama Kecamatan', 'Total (pasien)'];
                    $config['paging'] = false;
                    $config['searching'] = false;
                    $config['info'] = false;
                    $config['order'] = 2;
                @endphp
                <x-adminlte-datatable id="table1" :heads="$heads" :config="$config" hoverable bordered compressed>
                    @foreach ($pasiens_kecamatan as $item)
                        <tr>
                            <td>{{ $item->kode_kecamatan }}</td>
                            {{-- <td>{{ $kecamatan->where('kode_kecamatan', $item->kode_kecamatan)->first() ? $kecamatan->where('kode_kecamatan', $item->kode_kecamatan)->first()->nama_kecamatan : null }}
                            </td> --}}
                            <td>{{ \App\Models\Kecamatan::firstWhere('kode_kecamatan', $item->kode_kecamatan)->nama_kecamatan }}
                            </td>
                            <td>{{ $item->total }}</td>
                        </tr>
                    @endforeach
                </x-adminlte-datatable>
            </x-adminlte-card>
        </div>
        <div class="col-6">
            <x-adminlte-card title="Data Pasien Berdasarkan 20 Kabupaten Teratas" theme="secondary" collapsible>
                @php
                    $heads = ['Kode Kabupaten', 'Nama Kabupaten', 'Total (pasien)'];
                    $config['paging'] = false;
                    $config['searching'] = false;
                    $config['info'] = false;
                    $config['order'] = 2;
                @endphp
                <x-adminlte-datatable id="table2" :heads="$heads" :config="$config" hoverable bordered compressed>
                    @foreach ($pasiens_kabupaten as $item)
                        <tr>
                            <td>{{ $item->kode_kabupaten }}</td>
                            <td>{{ \App\Models\Kabupaten::firstWhere('kode_kabupaten_kota', $item->kode_kabupaten)->nama_kabupaten_kota }}
                            </td>
                            <td>{{ $item->total }}</td>
                        </tr>
                    @endforeach
                </x-adminlte-datatable>
            </x-adminlte-card>
        </div>
    </div>
@stop

@section('plugins.Datatables', true)
@section('plugins.Select2', true)
@section('plugins.TempusDominusBs4', true)
