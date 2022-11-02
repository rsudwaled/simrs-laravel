@extends('adminlte::page')

@section('title', 'Index Penyakit Rawat Jalan')

@section('content_header')
    <h1>Index Penyakit Rawat Jalan</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-12">
            <x-adminlte-card title="Filter Data Antrian" theme="secondary" collapsible>
                <form action="{{ route('index_penyakit_rajal') }}" method="get">
                    <div class="row">
                        <div class="col-md-3">
                            @php
                                $config = [
                                    'locale' => ['format' => 'YYYY/MM/DD'],
                                ];
                            @endphp
                            <x-adminlte-date-range name="tanggal" label="Periode Tanggal Kunjungan"
                                enable-default-ranges="This Month" :config="$config">
                                <x-slot name="prependSlot">
                                    <div class="input-group-text bg-primary">
                                        <i class="fas fa-calendar-alt"></i>
                                    </div>
                                </x-slot>
                            </x-adminlte-date-range>
                        </div>
                        <div class="col-md-3">
                            <x-adminlte-input name="diagnosa" value="{{ $request->diagnosa }}" label="Diagcosa ICD-10">
                                <x-slot name="prependSlot">
                                    <div class="input-group-text bg-primary">
                                        <i class="fas fa-disease"></i>
                                    </div>
                                </x-slot>
                            </x-adminlte-input>
                        </div>
                    </div>
                    <x-adminlte-button type="submit" class="withLoad" theme="success" label="Submit Pencarian"
                        icon="fas fa-search" />
                </form>
            </x-adminlte-card>
        </div>
        @isset($diagnosa)
            <div class="col-12">
                <div id="printMe">
                    <section class="invoice p-3 mb-3">
                        <div class="row">
                            <img src="{{ asset('vendor/adminlte/dist/img/rswaledico.png') }}" style="width: 100px">
                            <div class="col">
                                <b>RUMAH SAKIT UMUM DAERAH WALED</b><br>
                                <b>KABUPATEN CIREBON</b><br>
                                Jalan Raden Walangsungsang Kecamatan Waled Kabupaten Cirebon 45188<br>
                                www.rsudwaled.id - brsud.waled@gmail.com - Call Center (0231) 661126
                            </div>
                        </div>
                        <div class="row invoice-info">
                            <div class="col-sm-12 invoice-col text-center">
                                <b class="text-lg">LAPORAN INDEX PENYAKIT RAWAT JALAN</b>
                                <br>
                                <br>
                            </div>
                            <div class="col-sm-4 invoice-col">
                                <dl class="row">
                                    <dt class="col-sm-4 m-0">ICD-10</dt>
                                    <dd class="col-sm-8 m-0"> : <b>{{ strtoupper($request->diagnosa) }} - </b>
                                    </dd>
                                    <dt class="col-sm-4 m-0">Diagnosa</dt>
                                    <dd class="col-sm-8 m-0"> : <b>{{ strtoupper($request->diagnosa) }} - </b>
                                    </dd>
                                </dl>
                            </div>
                            <div class="col-sm-4 invoice-col">
                                <dl class="row">
                                    <dt class="col-sm-4 m-0">Periode</dt>
                                    <dd class="col-sm-8 m-0"> : <b>{{ $request->tanggal }}</b>
                                    </dd>
                                    <dt class="col-sm-4  m-0">Waktu Cetak</dt>
                                    <dd class="col-sm-8  m-0"> : <b>{{ Carbon\Carbon::now() }}</b>
                                    </dd>
                                </dl>
                            </div>
                            <div class="col-sm-4 invoice-col">
                                <dl class="row">
                                    <dt class="col-sm-4  m-0">User</dt>
                                    <dd class="col-sm-8  m-0"> : <b>{{ Auth::user()->name }}</b>
                                    </dd>

                                </dl>
                            </div>
                        </div>
                        <div class="col-12 table-responsive">
                            <table class="table table-sm text-xs">
                                <thead>
                                    <tr>
                                        <th rowspan="2">Tgl Kunjg.</th>
                                        <th rowspan="2">RM</th>
                                        <th rowspan="2">Nama</th>
                                        <th colspan="8">Umur</th>
                                        <th rowspan="2">Unit</th>
                                        <th rowspan="2">Pasien</th>
                                        <th rowspan="2">Kasus</th>
                                        <th rowspan="2">Diagnosa ICD-10</th>
                                        <th rowspan="2">Dokter</th>
                                    </tr>
                                    <tr>
                                        <th>0-28hr</th>
                                        <th>
                                            < 1th</th>
                                        <th>1-4th</th>
                                        <th>5-14th</th>
                                        <th>15-24th</th>
                                        <th>25-44th</th>
                                        <th>45-64th</th>
                                        <th>> 65th</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    @foreach ($diagnosa as $item)
                                        <tr>
                                            <td>{{ $item->tgl_masuk_kunjungan }}</td>
                                            <td>{{ $item->no_rm }}</td>
                                            <td>{{ $item->pasien->nama_px }}</td>
                                            @php
                                                $umur_day = \Carbon\Carbon::parse($item->pasien->tgl_lahir)->diffInDays(\Carbon\Carbon::parse($item->tgl_masuk_kunjungan));
                                                $umur_tahun = \Carbon\Carbon::parse($item->pasien->tgl_lahir)->diffInYears(\Carbon\Carbon::parse($item->tgl_masuk_kunjungan));
                                            @endphp
                                            <td>
                                                @if ($umur_day < 28)
                                                    <b> 1</b>
                                                @endif
                                            </td>
                                            <td>
                                                @if ($umur_tahun < 1)
                                                    <b> 1</b>
                                                @endif
                                            </td>
                                            <td>
                                                @if ($umur_tahun > 1 && $umur_tahun < 5)
                                                    <b> 1</b>
                                                @endif
                                            </td>
                                            <td>
                                                @if ($umur_tahun > 5 && $umur_tahun < 15)
                                                    <b> 1</b>
                                                @endif
                                            </td>
                                            <td>
                                                @if ($umur_tahun > 15 && $umur_tahun < 25)
                                                    <b> 1</b>
                                                @endif
                                            </td>
                                            <td>
                                                @if ($umur_tahun > 25 && $umur_tahun < 45)
                                                    <b> 1</b>
                                                @endif
                                            </td>
                                            <td>
                                                @if ($umur_tahun > 45 && $umur_tahun < 65)
                                                    <b> 1</b>
                                                @endif
                                            </td>
                                            <td>
                                                @if ($umur_tahun > 65)
                                                    <b> 1</b>
                                                @endif
                                            </td>
                                            <td>{{ $item->nama_unit }}</td>
                                            <td>
                                                @if ($item->kunjungan_baru)
                                                    Baru
                                                @else
                                                    Lama
                                                @endif
                                            </td>
                                            <td>
                                                @if ($item->kasus_baru)
                                                    Baru
                                                @else
                                                    Lama
                                                @endif
                                            </td>
                                            <td>
                                                {{ $item->diag_utama }} - {{ $item->diag_utama_desc }}
                                            </td>
                                            <td>{{ $item->dokter ? $item->dokter->nama_paramedis : null }}</td>
                                        </tr>
                                    @endforeach
                                </tbody>
                            </table>
                        </div>
                    </section>
                </div>
                <button class="btn btn-success" onclick="printDiv('printMe')"><i class="fas fa-print"> Print Laporan</i>
            </div>
        @endisset
    </div>
@stop

@section('plugins.Datatables', true)
@section('plugins.DatatablesPlugins', true)
@section('plugins.DateRangePicker', true)
@section('plugins.Chartjs', true)
@section('js')
    <script>
        function printDiv(divName) {
            var printContents = document.getElementById(divName).innerHTML;
            var originalContents = document.body.innerHTML;
            tampilan_print = document.body.innerHTML = printContents;
            setTimeout('window.addEventListener("load", window.print());', 1000);
        }
    </script>
@endsection
@section('css')
    <style type="text/css" media="print">
        @media print {
            @page {
                size: landscape
            }
        }

        table,
        th,
        td {
            border: 1px solid #333333 !important;
        }
    </style>

@endsection
