@extends('adminlte::page')

@section('title', 'Status  Bridging | SIM RSUD Waled')

@section('content_header')
    <h1 class="m-0 text-dark">Status  Bridging</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-12">
            <div class="row">
                <div class="col-md-3">
                    <x-adminlte-small-box title="{{ $peserta->metaData->code == 200 ? 'ON' : 'OFF' }}"
                        text="Bridging Vclaim BPJS" theme="{{ $peserta->metaData->code == 200 ? 'success' : 'danger' }}"
                        icon="fas {{ $peserta->metaData->code == 200 ? 'fa-wifi' : 'fa-wifi-slash' }}" />
                </div>
                <div class="col-md-3">
                    <x-adminlte-small-box title="{{ $poli->metadata->code == 1 ? 'ON' : 'OFF' }}"
                        text="Bridging Antrian BPJS" theme="{{ $poli->metadata->code == 1 ? 'success' : 'danger' }}"
                        icon="fas {{ $poli->metadata->code == 1 ? 'fa-wifi' : 'fa-wifi-slash' }}" />
                </div>
                {{-- <div class="col-md-3">
                    <x-adminlte-small-box title="{{ $kunjungans->count() }}" text="Total Kunjungan Pasien" theme="warning"
                        icon="fas fa-users" />
                </div>
                <div class="col-md-3">
                    <x-adminlte-small-box title="{{ round(($antrians->count() / $kunjungans->count()) * 100) }} % "
                        text="Persentase Pemutakhir Data" theme="primary" icon="fas fa-users" />
                </div> --}}
            </div>
        </div>
    </div>
@stop
