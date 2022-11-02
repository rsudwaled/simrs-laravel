@extends('adminlte::page')

@section('title', 'Referensi Tarif Kelompok Layanan')

@section('content_header')
    <h1>Referensi Tarif Kelompok Layanan</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-12">
            <x-adminlte-card title="Data Informasi Tarif Kelompok Layanan" theme="info" icon="fas fa-info-circle" collapsible maximizable>
                @php
                    $heads = ['No.', 'Nama Kelompok Tarif', 'Prefix', 'Group', 'Vclaim','Keterangan'];
                @endphp
                <x-adminlte-datatable id="table1" :heads="$heads" striped bordered hoverable compressed>
                    @foreach ($tarifkelompoks as $item)
                        <tr>
                            <td>{{ $item->id }}</td>
                            <td>{{ $item->namatarifkelompok }}</td>
                            <td>{{ $item->prefix }}</td>
                            <td>{{ $item->grouptarif }}</td>
                            <td>{{ $item->groupvclaim }}</td>
                            <td>{{ $item->keterangan }}</td>
                            {{-- <td> --}}
                                {{-- @if ($item->status == 1)
                                    <a href="{{ route('dokter.show', $item->kodedokter) }}">
                                        <x-adminlte-button class="btn-xs" type="button" label="aktif"
                                            theme="success" />
                                    </a>
                                @else
                                    <a href="{{ route('dokter.show', $item->kodedokter) }}">
                                        <x-adminlte-button class="btn-xs" type="button" label="nonaktif"
                                            theme="danger" />
                                    </a>
                                @endif --}}
                            {{-- </td> --}}
                        </tr>
                    @endforeach
                </x-adminlte-datatable>
                <a href="{{ route('tarif_kelompok_layanan.create') }}" class="btn btn-success">Refresh</a>
            </x-adminlte-card>
        </div>
    </div>
@stop

@section('plugins.Select2', true)
@section('plugins.Datatables', true)
