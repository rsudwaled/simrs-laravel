@extends('adminlte::page')

@section('title', 'Laporan Antrian Per Tanggal')

@section('content_header')
    <h1>Laporan Antrian Per Tanggal</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-12">
            <x-adminlte-card title="Filter Data Antrian" theme="secondary" collapsible>
                <form action="{{ route('antrian.laporan_bulan') }}" method="get">
                    <div class="row">
                        <div class="col-md-3">
                            @php
                                $config = ['format' => 'YYYY-MM'];
                            @endphp
                            <x-adminlte-input-date name="tanggal" label="Tanggal Laporan" value="{{ $request->tanggal }}"
                                :config="$config">
                                <x-slot name="prependSlot">
                                    <div class="input-group-text bg-primary">
                                        <i class="fas fa-calendar-alt"></i>
                                    </div>
                                </x-slot>
                            </x-adminlte-input-date>
                        </div>
                        <div class="col-md-3">
                            <x-adminlte-select label="Waktu Server" name="waktu">
                                <option value="rs">Server RS</option>
                                <option value="server">Server BPJS</option>
                            </x-adminlte-select>
                        </div>
                    </div>
                    <x-adminlte-button type="submit" class="withLoad" theme="primary" label="Submit Antrian" />
                </form>
            </x-adminlte-card>
            @if (isset($antrians))
                <x-adminlte-card title="Antrian Pendaftaran" theme="primary" icon="fas fa-info-circle" collapsible>
                    @if ($errors->any())
                        <x-adminlte-alert title="Ops Terjadi Masalah !" theme="danger" dismissable>
                            <ul>
                                @foreach ($errors->all() as $error)
                                    <li>{{ $error }}</li>
                                @endforeach
                            </ul>
                        </x-adminlte-alert>
                    @endif
                    @php
                        $heads = ['Tanggal', 'Nama Poli', 'Checkin', 'Pendaftaran', 'Tunggu Poli', 'Layanan Poli', 'Tunggu Farmasi', 'Layanan Farmasi', 'Jumlah'];
                        $config['order'] = ['2', 'desc'];
                    @endphp
                    <x-adminlte-datatable id="table1" class="nowrap" :heads="$heads" :config="$config" striped bordered
                        hoverable compressed>
                        @foreach ($antrians as $item)
                            <tr>
                                <td>{{ $item->tanggal }}</td>
                                <td>{{ $item->namapoli }}</td>
                                <td>Total : {{ round($item->waktu_task1 / 60) }} menit <br>
                                    Rata : {{ round($item->avg_waktu_task1 / 60) }} menit
                                </td>
                                <td>Total : {{ round($item->waktu_task2 / 60) }} menit<br>
                                    Rata : {{ round($item->avg_waktu_task2 / 60) }} menit
                                </td>
                                <td>Total : {{ round($item->waktu_task3 / 60) }} menit<br>
                                    Rata : {{ round($item->avg_waktu_task3 / 60) }} menit
                                </td>
                                <td>Total : {{ round($item->waktu_task4 / 60) }} menit<br>
                                    Rata : {{ round($item->avg_waktu_task4 / 60) }} menit
                                </td>
                                <td>Total : {{ round($item->waktu_task5 / 60) }} menit<br>
                                    Rata : {{ round($item->avg_waktu_task5 / 60) }} menit
                                </td>
                                <td>Total : {{ round($item->waktu_task6 / 60) }} menit<br>
                                    Rata : {{ round($item->avg_waktu_task6 / 60) }} menit
                                </td>
                                <td>{{ $item->jumlah_antrean }}</td>
                                {{-- <td>{{ date('d/m/Y H:i:s', $item->insertdate / 1000) }}</td> --}}
                            </tr>
                        @endforeach
                    </x-adminlte-datatable>
                </x-adminlte-card>
            @endif
        </div>
    </div>
@stop

@section('plugins.Select2', true)
@section('plugins.Datatables', true)
@section('plugins.TempusDominusBs4', true)
@section('plugins.DateRangePicker', true)
