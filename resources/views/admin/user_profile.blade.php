@extends('adminlte::page')

@section('title', 'Profil ' . $user->name)

@section('content_header')
    <h1>Profil {{ $user->name }}</h1>
@stop

@section('content')
    <div class="row">
        <div class="col-md-4">
            <x-adminlte-profile-widget name="{{ $user->name }}" desc="{{ $user->email }}" theme="primary"
                img="https://picsum.photos/id/1/100">
                {{-- <x-adminlte-profile-col-item title="Followers" text="125" url="#" />
                <x-adminlte-profile-col-item title="Following" text="243" url="#" />
                <x-adminlte-profile-col-item title="Posts" text="37" url="#" /> --}}
                <ul class="nav flex-column col-md-12">
                    <li class="nav-item">
                        <b class="nav-link">Nama <b class="float-right ">{{ $user->name }}</b></b>
                    </li>
                    <li class="nav-item">
                        <b class="nav-link">Username <b class="float-right ">{{ $user->username }}</b></b>
                    </li>
                    <li class="nav-item">
                        <b class="nav-link">Phone <b class="float-right ">{{ $user->phone }}</b></b>
                    </li>
                    <li class="nav-item">
                        <b class="nav-link">Email <b class="float-right ">{{ $user->email }}</b></b>
                    </li>
                </ul>

            </x-adminlte-profile-widget>
        </div>
        <div class="col-md-8">
        </div>
    </div>
@stop
